#!/usr/bin/env python3

import ssl
import json
import socket
import threading

serv_addr = '127.0.0.1'
serv_port = 60000

class Server:
    def __init__(self, serv_addr, serv_port):
        self.serv_addr = serv_addr
        self.serv_port = serv_port
        self.users = []

    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain('ssl/cert.pem', 'ssl/cert.key')
        self.socket = self.context.wrap_socket(self.socket, server_side=True)
        try:
            self.socket.bind((self.serv_addr, self.serv_port))
            print(f"Address '{serv_addr}:{str(serv_port)}' is binded")
            self.socket.listen()
            print("Server is listening")
            while True:
                try:
                    conn, addr = self.socket.accept()
                except ssl.SSLError:
                    continue
                log = {"address": addr[0], "type": "server", 
                        "message": "connected!"}
                print(f"Address: {log['address']}, Type: {log['type']}, "\
                        f"Message: {log['message']}")
                for user in self.users:
                    user.send(json.dumps(log).encode())
                conn.send('{"address": "SERVER", "type": "server", '\
                        '"message": "Welcome to the server!"}'.encode())
                self.users.append(conn)
                clientHandlerThread = threading.Thread(
                        target=self.clientHandler,
                        args=(conn,addr,),
                        daemon=True
                        )
                clientHandlerThread.start()
        finally:
            self.socket.close()
                
    def clientHandler(self, conn, addr):
        try:
            while True:
                data = conn.recv(2048)
                if not data:
                    log = {"address": addr[0], "type": "server", 
                            "message": "disconnected!"}
                    print(f"Address: {log['address']}, Type: {log['type']}, "\
                            f"Message: {log['message']}")
                    self.users.remove(conn)
                    for user in self.users:
                        user.send(json.dumps(log).encode())
                    conn.close()
                    return
                try:
                    data = json.loads(data.decode())
                    header = data['header']
                    message = data['message']
                    message_type = data['type']
                except (json.decoder.JSONDecodeError, KeyError):
                    log = {"address": "", "type": "server", 
                            "message": "Wrong request!"}
                    print(f"Address: {log['address']}, Type: {log['type']}, "\
                            f"Message: {log['message']}")
                    conn.send(json.dumps(log).encode())
                    continue
                if header == "message" and (message_type == "plain-text" or
                        message_type == "encrypted"):
                    log = {"address": addr[0], "type": message_type, 
                            "message": message}
                    print(f"Address: {log['address']}, Type: {log['type']}, "\
                            f"Message: {log['message']}")
                    for user in self.users:
                        if user != conn:
                            user.send(json.dumps(log).encode())
            conn.close()
        except ConnectionResetError:
            conn = None
            self.users.remove(conn)

if __name__ == "__main__":
    server = Server(serv_addr, serv_port)
    try:
        server.start()
    except (KeyboardInterrupt, SystemExit):
        print()
        exit(0)
