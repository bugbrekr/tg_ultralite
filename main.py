import flask
import database
import time
import hashlib
import secrets
# import threading
import telegram
import re
from htmlmin.main import minify
import html

app = flask.Flask(__name__, static_url_path='/tg/', static_folder='static')

SYSTEM_LOCK_THRESHOLD = 5
LOGIN_VALIDITY_DURATION = 3600
PUBLIC_ENDPOINTS = ["/tg/login", "/tg/login/verify", "/tg/system_locked"]

DIALOGS_PER_PAGE = 10
MESSAGES_PER_PAGE = 10

tokendb = database.JSONDatabase("db/tokendb.json")
accountsdb = database.JSONDatabase("db/accountsdb.json")
securitydb = database.JSONDatabase("db/securitydb.json")
tg_sessiondb = database.MessagePackDatabase("db/tg_sessiondb.msgpack")

tg_clients = {}
with open("db/tg_socket_path") as f:
    tg_server_socket_path = f.read()
    print("Using Telegram Server socket at: "+tg_server_socket_path)
# def run_telegram_server():
#     global tg_server_socket_path
#     s = telegram.TelegramServer()
#     tg_server_socket_path = s.socket_path
#     print('running')
#     s.run()

def purge_expired_tokens():
    for key, value in tokendb.items():
        if time.time() >= value["expiry_timestamp"]:
            tokendb.pop(key)

def verify_token(access_token):
    if access_token == None:
        return False
    token = tokendb.get(access_token)
    if token == None:
        return False
    if time.time() >= token.get("expiry_timestamp"):
        tokendb.pop(access_token)
        return False
    return True

def generate_access_token():
    while True:
        access_token = secrets.token_hex(32)
        if access_token not in tokendb:
            break
    return access_token

def get_tg_client(session_id):
    global tg_clients
    if tg_clients.get(session_id) != None:
        return tg_clients[session_id]
    if tg_sessiondb.get(session_id) == None:
        raise KeyError("Session data not found")
    tg_client = telegram.TelegramClient(tg_server_socket_path, session_id, tg_sessiondb[session_id])
    tg_clients[session_id] = tg_client
    return tg_client

def clean_string(s):
    if s == None: return None
    return re.sub('[^abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \n:/\|.,<>[]}{-_=+`~!@#$%^&*()\'\";:]', '', s)

def get_chat_name(c):
    if c.first_name != None:
        return c.first_name+(" "+c.last_name if c.last_name else "")
    else:
        return c.title

@app.route("/tg/", defaults={'page': 0})
@app.route("/tg/<int:page>")
def chat_list(page):
    token_data = tokendb[flask.request.cookies['access_token']]
    tg = get_tg_client(token_data['username'])
    total_unread_counter = 0
    unread_chats = 0
    chats = []
    tg_chats = tg.call("get_chats", DIALOGS_PER_PAGE*(page+1))
    for c in tg_chats:
        if c["unread_messages_count"] > 0:
            total_unread_counter += c["unread_messages_count"]
            unread_chats += 1
    is_last_page = len(tg_chats) < DIALOGS_PER_PAGE*(page+1)
    tg_chats = tg_chats[-DIALOGS_PER_PAGE:]
    for c in tg_chats:
        chat = {}
        chat["name"] = clean_string(get_chat_name(c["chat"]))
        if c["is_pinned"] == True:
            if c["is_self"] == False:
                continue
            else:
                chat["name"] = "Saved Messages"
        chat["id"] = c["chat"].id
        if c["top_message"].text != None:
            chat["last_message"] = (
                clean_string(str(c["top_message"].text)[:30]+("..." if len(c["top_message"].text)>30 else "")).replace("\n", " "), 
                clean_string((c["top_message"].from_user.first_name if c["top_message"].from_user!=None else get_chat_name(c["top_message"].sender_chat)))
            )
        elif c["top_message"].media != None:
            chat["last_message"] = (
                clean_string(c["top_message"].media.value.capitalize()+(", "+c["top_message"].caption[:25]+("..." if len(c["top_message"].caption)>25 else "") if c["top_message"].caption!=None else "")).replace("\n", " "),
                clean_string((c["top_message"].from_user.first_name if c["top_message"].from_user!=None else get_chat_name(c["top_message"].sender_chat)))
            )
        else:
            chat["last_message"] = (
                "<SERVICE MESSAGE>",
                None
            )
        chat["last_message_time"] = c["top_message"].date.strftime("%H:%M")
        chat["unread_counter"] = c["unread_messages_count"]
        chats.append(chat)
    return flask.render_template("chats.html", chats=chats, total_unread_counter=total_unread_counter, unread_chats=unread_chats, current_page=page, is_last_page=is_last_page, DIALOGS_PER_PAGE=DIALOGS_PER_PAGE)

@app.route("/tg/chat/", defaults={'chat_id': "0", 'page': 0})
@app.route("/tg/chat/<chat_id>/", defaults={'page': 0})
@app.route("/tg/chat/<chat_id>/<int:page>")
def chat_page(chat_id, page):
    chat_id = int(chat_id)
    if chat_id == 0:
        return flask.redirect("/tg/")
    token_data = tokendb[flask.request.cookies['access_token']]
    tg = get_tg_client(token_data['username'])
    history = tg.call("get_chat_history", chat_id=chat_id, limit=MESSAGES_PER_PAGE, offset=page*MESSAGES_PER_PAGE)[::-1]
    messages = []
    for _msg in history:
        msg = {}
        if _msg.text != None:
            msg["type"] = "text"
            msg["text"] = html.escape(_msg.text).replace("\n", "<br>")
        msg["timestamp"] = _msg.date.strftime("%H:%M")
        msg["sender"] = {"name": clean_string((_msg.from_user.first_name if _msg.from_user!=None else get_chat_name(_msg.sender_chat)))}
        messages.append(msg)
    return flask.render_template("chat.html", chat_name="Saved Messages", chat_id=chat_id, page=page, messages=messages)

@app.route("/tg/sendTextMessage")
def sendTextMessage():
    msg = flask.request.args["message"].strip()
    chat_id = flask.request.args["chat_id"]
    if msg == "":
        return flask.redirect(f"/tg/chat/{chat_id}/"), 302
    token_data = tokendb[flask.request.cookies['access_token']]
    tg = get_tg_client(token_data['username'])
    tg.call("send_text_message", chat_id=chat_id, text=msg)
    return flask.redirect(f"/tg/chat/{chat_id}/"), 302

@app.route("/tg/test")
def test_page():
    return flask.render_template("test.html")

@app.route("/tg/test2", methods=["GET", "POST"])
def test_endpoint():
    print(flask.request.headers)
    print(flask.request.data)
    print(flask.request.stream.read(4096))
    print(flask.request.form)
    print(flask.request.args)
    print(flask.request.files)
    return flask.redirect("/tg/test")

@app.route("/tg/login")
def login_page():
    if securitydb["retries"] >= SYSTEM_LOCK_THRESHOLD:
        return flask.redirect("/tg/system_locked")
    return flask.render_template("login.html")

@app.route("/tg/login/verify")
def verify_login():
    if flask.request.args.get("username") == None or flask.request.args.get("password") == None:
        return flask.redirect("/tg/login")
    username = flask.request.args["username"].strip()
    if username == "" or flask.request.args["password"].strip() == "":
        return flask.redirect("/tg/login")
    if accountsdb.get(username) == None:
        return flask.redirect("/tg/login")
    ip_addr = flask.request.headers.get('X-Forwarded-For')
    user_agent = flask.request.headers.get('User-Agent')
    password_hash = hashlib.sha256(flask.request.args["password"].strip().encode()).hexdigest()
    if password_hash != accountsdb[username]["password_hash"]:
        securitydb["retries"] += 1
        incident_data = {
            "username": username,
            "login_timestamp": int(time.time()),
            "ip_addr": ip_addr,
            "user_agent": user_agent,
            "updated_retry_count": securitydb["retries"]
        }
        incidents = securitydb["incidents"]
        incidents.append(incident_data)
        securitydb["incidents"] = incidents
        return flask.redirect("/tg/login")
    access_token = generate_access_token()
    token_data = {
        "username": username,
        "login_timestamp": int(time.time()),
        "expiry_timestamp": int(time.time())+LOGIN_VALIDITY_DURATION,
        "ip_addr": ip_addr,
        "user_agent": user_agent
    }
    tokendb[access_token] = token_data
    securitydb["retries"] = 0
    resp = flask.make_response(flask.redirect("/tg/"))
    resp.set_cookie("access_token", access_token)
    purge_expired_tokens()
    return resp

@app.route("/tg/system_locked")
def system_locked_message():
    if securitydb["retries"] < SYSTEM_LOCK_THRESHOLD:
        return flask.redirect("/tg/")
    return flask.render_template("system_locked.html")

@app.before_request
def before_request():
    if flask.request.path in PUBLIC_ENDPOINTS:
        return
    if not verify_token(flask.request.cookies.get('access_token')):
        return flask.redirect("/tg/login")

@app.after_request
def response_minify(response):
    if response.content_type == u'text/html; charset=utf-8':
        response.set_data(
            minify(response.get_data(as_text=True))
        )
        return response
    return response

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8027)