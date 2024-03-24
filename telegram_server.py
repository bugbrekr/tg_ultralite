import telegram

def run_server():
    s = telegram.TelegramServer()
    with open("db/tg_socket_path", "w") as f:
        f.write(s.socket_path)
    print("Running on:", s.socket_path)
    s.run()

run_server()
