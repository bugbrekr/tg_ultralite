import pyrogram
import pickle
import socket
import secrets
import struct
import asyncio
import traceback
import toml

with open("config.toml") as f:
    config = toml.loads(f.read())

API_ID = config["telegram"]["API_ID"]
API_HASH = config["telegram"]["API_HASH"]

class TelegramSession:
    def __init__(self, session_data, session_id=None, api_id=API_ID, api_hash=API_HASH):
        if session_id == None:
            session_id = secrets.token_hex(16)
        self.tgs = pyrogram.Client(
            session_id,
            session_string=session_data,
            api_id=api_id,
            api_hash=api_hash,
            no_updates=False,
            in_memory=True,
            hide_password=True,
            device_model="TG Flipped",
            app_version="TG Flipped 1.0"
        )
        self.tgs.start()
        self.meuser = self.tgs.get_me()
    def _get_session_data(self):
        return self.tgs.export_session_string()
    def close(self):
        session_data = self._get_session_data()
        self.tgs.stop()
        return session_data
    def get_chats(self, n=10):
        chats = []
        for c in self.tgs.get_dialogs(n):
            dc = {
                "chat": c.chat,
                "top_message": c.top_message,
                "unread_messages_count": c.unread_messages_count,
                "unread_mentions_count": c.unread_mentions_count,
                "unread_mark": c.unread_mark,
                "is_pinned": c.is_pinned,
                "is_self": False
            }
            if c.chat.id == self.meuser.id:
                dc["is_self"] = True
            chats.append(dc)
        return chats
    def get_chat_history(self, chat_id, limit=10, offset=-1, offset_id=-1):
        history = []
        for m in self.tgs.get_chat_history(chat_id=chat_id, limit=limit, offset=offset, offset_id=offset_id):
            history.append(m)
        return history
    def send_text_message(self, chat_id, text, read_max_id=0):
        msg_id = self.tgs.send_message(chat_id=chat_id, text=text)
        self.read_chat_history(chat_id=chat_id, max_id=read_max_id)
        return msg_id
    def read_chat_history(self, chat_id, max_id=0):
        return self.tgs.read_chat_history(chat_id=chat_id, max_id=max_id)
    def get_chat(self, chat_id):
        return self.tgs.get_chat(chat_id=chat_id)
    def download_media(self, message, file_name=None):
        return self.tgs.download_media(message=message, file_name=file_name, in_memory=False, block=True)

class TelegramServer:
    def __init__(self, socket_path=None):
        if socket_path == None:
            socket_path = "/tmp/"+secrets.token_hex(16)
        self.socket_path = socket_path
        self.s_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s_sock.bind(self.socket_path)
        self.s_sock.listen(0)
        self.sessions = {}
    def _recvall(self, sock, n):
        data = bytearray()
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data
    def _recv_msg(self, sock):
        raw_msglen = self._recvall(sock, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        return self._recvall(sock, msglen)
    def _send_msg(self, sock, data):
        data = struct.pack('>I', len(data)) + data
        try:
            sock.sendall(data)
            return data
        except:
            return None
    def _send(self, sock, data):
        packed_data = pickle.dumps(data)
        self._send_msg(sock, packed_data)
    def _recv(self, sock):
        packed_data = self._recv_msg(sock)
        if not packed_data: return None
        data = pickle.loads(packed_data)
        return data
    def request_handler(self, session_id, method, args, kwargs, raw=False):
        if session_id not in self.sessions:
            return False, {"type": "SessionNotInitialized"}
        tg = self.sessions[session_id]
        try:
            if raw==True:
                resp = getattr(tg.tgs, method)(*args, **kwargs)
                return True, resp
            resp = getattr(tg, method)(*args, **kwargs)
            return True, resp
        except Exception:
            print("RUNTIME ERROR:")
            traceback.print_exc(chain=False)
            return False, {"type": "RuntimeError", "traceback": traceback.format_exc(chain=False)}
    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        while True:
            try:
                sock, _, = self.s_sock.accept()
                while True:
                    data = self._recv(sock)
                    if not data:
                        sock.close()
                        break
                    if data['type'] == "call_method":
                        resp_status, resp_data = self.request_handler(data['session_id'], data['method'], tuple(data['args']), data['kwargs'])
                        self._send(sock, {"status": resp_status, "data": resp_data})
                    elif data['type'] == "raw_call_method":
                        resp_status, resp_data = self.request_handler(data['session_id'], data['method'], tuple(data['args']), data['kwargs'], raw=True)
                        self._send(sock, {"status": resp_status, "data": resp_data})
                    elif data['type'] == "init_session":
                        session_id, session_data = data["session_id"], data["session_data"]
                        self.sessions[session_id] = TelegramSession(session_data, session_id)
                        self._send(sock, {"status": True, "data": None})
                    elif data['type'] == "get_session_data":
                        if session_id not in self.sessions:
                            self._send(sock, {"status": False, "data": {"type": "SessionNotInitialized"}})
                        session_data = self.sessions[session_id]._get_session_data()
                        self._send(sock, {"status": True, "data": session_data})
                    elif data['type'] == "close_session":
                        if session_id not in self.sessions:
                            self._send(sock, {"status": False, "data": {"type": "SessionNotInitialized"}})
                        session_data = self.sessions[session_id].close()
                        self.sessions.pop(session_data)
                        self._send(sock, {"status": True, "data": session_data})
                    sock.close()
                    break
            except:
                print("------------------START CRITICAL RUNTIME ERROR------------------")
                traceback.print_exc(chain=False)
                print("-------------------END CRITICAL RUNTIME ERROR------------------")

class TelegramClient:
    class RuntimeError(Exception):
        pass
    class SessionNotInitializedError(Exception):
        pass
    def __init__(self, socket_path, session_id=None, session_data=""):
        self.socket_path = socket_path
        self.session_data = session_data
        self.session_id = secrets.token_hex(16) if session_id == None else session_id
        self.send({"type": "init_session", "session_id": self.session_id, "session_data": session_data})
    def _recvall(self, sock, n):
        data = bytearray()
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data
    def _recv_msg(self):
        raw_msglen = self._recvall(self.sock, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        return self._recvall(self.sock, msglen)
    def _send_msg(self, data):
        data = struct.pack('>I', len(data)) + data
        self.sock.sendall(data)
    def _send(self, data):
        try:
            packed_data = pickle.dumps(data)
        except TypeError:
            pass
        self._send_msg(packed_data)
    def _recv(self):
        packed_data = self._recv_msg()
        if not packed_data:
            return None
        data = pickle.loads(packed_data)
        return data
    def _disconnect(self):
        self.sock.close()
    def _connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.socket_path)
    def send(self, data):
        self._connect()
        self._send(data)
        resp_data = self._recv()
        self._disconnect()
        return resp_data
    def get_session_data(self):
        return self.send({"type": "get_session_data"})
    def _dynamic_command_handler(self, method_name, args, kwargs, raw=False):
        if raw==True:
            resp = self.send({"session_id": self.session_id, "type": "raw_call_method", "method": method_name, "args": args, "kwargs": kwargs})
        else:
            resp = self.send({"session_id": self.session_id, "type": "call_method", "method": method_name, "args": args, "kwargs": kwargs})
        status = resp['status']
        data = resp['data']
        if status == True:
            return data
        elif data['type'] == "RuntimeError":
            err = "\n------------------START TELEGRAM SERVER SAYS------------------\n"+data["traceback"]+"--------------------END TELEGRAM SERVER SAYS------------------"
            raise RuntimeError(err)
        elif data['type'] == "SessionNotInitialized":
            raise self.SessionNotInitializedError(f"Session not initialized for {self.session_id}")
    def call(self, method_name, *args, **kwargs):
        return self._dynamic_command_handler(method_name, args, kwargs)
    def call_raw(self, method_name, *args, **kwargs):
        return self._dynamic_command_handler(method_name, args, kwargs, raw=True)
