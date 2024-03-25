import flask
import os
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
PUBLIC_ENDPOINTS = ["/tg/login", "/tg/login/verify", "/tg/system_locked", "/tg/media_download/"]

DIALOGS_PER_PAGE = 10
MESSAGES_PER_PAGE = 10

tokendb = database.JSONDatabase("db/tokendb.json")
accountsdb = database.JSONDatabase("db/accountsdb.json")
securitydb = database.JSONDatabase("db/securitydb.json")
tg_sessiondb = database.MessagePackDatabase("db/tg_sessiondb.msgpack")
mediadb = database.MessagePackDatabase("db/mediadb.msgpack")
if not os.path.isdir("db"):
    os.mkdir("db")
if not os.path.isdir("cache"):
    os.mkdir("cache")

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

def get_chat_from_message(m):
    if m.from_user != None:
        return m.from_user
    elif m.sender_chat != None:
        return m.sender_chat

def get_forwarded_msg_information(m):
    if m.forward_from != None:
        name = get_chat_name(m.forward_from)
        chat_id = m.forward_from.id
    elif m.forward_sender_name != None:
        name = m.forward_sender_name
        chat_id = None
    elif m.forward_from_chat != None:
        name = get_chat_name(get_chat_from_message(m.forward_from_chat))
        chat_id = m.forward_from_chat.id
    else:
        return None
    return name, chat_id

def get_friendly_name_for_media(media):
    return media.value.replace("_", " ").title()

def mimetype_to_ext(mimetype):
    match mimetype:
        case "image/jpeg":
            return ".jpg"
        case "image/png":
            return ".png"
        case "image/gif":
            return ".gif"
        case "audio/mpeg":
            return ".mp3"

def download_media(tg, file_id):
    while True:
        file_path = secrets.token_hex(32)
        if not os.path.isfile(f"cache/{file_path}"):
            break
    tg.call("download_media", message=file_id, file_name=f"cache/{file_path}")
    return file_path

def register_media(file, media_type):
    mime_type = None
    if hasattr(file, "mime_type"):
        mime_type = file.mime_type
    else:
        if media_type == "photo":
            mime_type = "image/jpeg"
        elif media_type == "video":
            mime_type = "video/mp4"
        elif media_type == "video_note":
            mime_type = "video/mp4"
    has_thumbs = bool(hasattr(file, "thumbs") and file.thumbs and file.thumbs[0].file_id != file.file_id)
    mediadb[file.file_unique_id] = {"mime_type": mime_type, "file_name": file.file_name if hasattr(file, "file_name") else None, "has_thumbs": has_thumbs, "file_id": file.file_id}
    if has_thumbs:
        thumbdata = {"file_id": file.thumbs[0].file_id, "width": file.thumbs[0].width, "height": file.thumbs[0].height}
        mdata = mediadb[file.file_unique_id]
        mdata["thumb"] = thumbdata
        mediadb[file.file_unique_id] = mdata

def download_thumb(tg, file, media_type):
    mdata = mediadb.get(file.file_unique_id)
    if mdata != None:
        if mdata["has_thumbs"]:
            if mdata["thumb"].get("file_path"):
                return mdata["thumb"]["file_path"]
        else:
            return None
    else:
        register_media(file, media_type)
    mdata = mediadb.get(file.file_unique_id)
    if not mdata["has_thumbs"]:
        return None
    file_path = download_media(tg, file.thumbs[0].file_id)
    mdata["thumb"]["file_path"] = file_path
    mediadb[file.file_unique_id] = mdata
    return file_path

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
                clean_string(get_friendly_name_for_media(c["top_message"].media)+(", "+c["top_message"].caption[:25]+("..." if len(c["top_message"].caption)>25 else "") if c["top_message"].caption!=None else "")).replace("\n", " "),
                clean_string((c["top_message"].from_user.first_name if c["top_message"].from_user!=None else get_chat_name(c["top_message"].sender_chat)))
            )
        elif c["top_message"].service != None:
            chat["last_message"] = (
                "<SERVICE MESSAGE>",
                None
            )
        else:
            chat["last_message"] = (
                "<NON-MESSAGE>",
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
    chat_name = get_chat_name(tg.call("get_chat", chat_id=chat_id))
    history = tg.call("get_chat_history", chat_id=chat_id, limit=MESSAGES_PER_PAGE, offset=page*MESSAGES_PER_PAGE)[::-1]
    messages = []
    for _msg in history:
        msg = {}
        if _msg.text != None:
            msg["type"] = "text"
            msg["text"] = html.escape(_msg.text).replace("\n", "<br>")
        elif _msg.media != None:
            msg["type"] = "media"
            msg["media_type"] = _msg.media.value
            if _msg.media.value in ["audio", "document", "photo", "video", "animation", "voice", "video_note"]:
                media_data = getattr(_msg, _msg.media.value)
                download_thumb(tg, media_data, _msg.media.value)
                msg["has_thumbs"] = mediadb[media_data.file_unique_id]["has_thumbs"]
                msg["media_file_unique_id"] = media_data.file_unique_id
                msg["media_file_name"] = mediadb[media_data.file_unique_id]["file_name"]
            else:
                print(_msg)
                msg["has_thumbs"] = False
            msg["caption"] = _msg.caption
        msg["forwarded"] = get_forwarded_msg_information(_msg)
        msg["timestamp"] = _msg.date.strftime("%H:%M")
        msg["datestamp"] = _msg.date.strftime("%B %-d, %Y")
        msg["sender"] = {"name": clean_string(get_chat_name(get_chat_from_message(_msg)))}
        messages.append(msg)
    return flask.render_template("chat.html", chat_name=chat_name, chat_id=chat_id, page=page, messages=messages)

@app.route("/tg/media_preview/<file_unique_id>")
def media_preview(file_unique_id):
    mdata = mediadb.get(file_unique_id)
    if mdata == None or not mdata["has_thumbs"]:
        return "NOT FOUND", 404
    file_path = mdata["thumb"]["file_path"]
    return flask.send_file(f"cache/{file_path}", mimetype="image/jpeg", download_name=mdata["file_name"])

@app.route("/tg/media_download/<file_unique_id>")
def media_download(file_unique_id):
    mdata = mediadb.get(file_unique_id)
    if mdata.get("file_path") == None:
        token_data = tokendb[flask.request.cookies['access_token']]
        tg = get_tg_client(token_data['username'])
        mdata["file_path"] = download_media(tg, mdata["file_id"])
        mediadb[file_unique_id] = mdata
    file_path = mdata["file_path"]
    mime_type = mdata["mime_type"]
    file_name = mdata["file_name"]
    if mime_type == "image/jpeg":
        file_name = file_name if file_name else secrets.token_hex(8)+".jpg"
    elif mime_type == "audio/ogg":
        file_name = file_name if file_name else secrets.token_hex(8)+".ogg"
    elif mime_type == "video/mp4":
        file_name = file_name if file_name else secrets.token_hex(8)+".mp4"
    return flask.send_file(f"cache/{file_path}", mimetype=mime_type, download_name=file_name, as_attachment=True)

@app.route("/tg/sendTextMessage")
def send_text_message():
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
    for path in PUBLIC_ENDPOINTS:
        if flask.request.path.startswith(path):
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
