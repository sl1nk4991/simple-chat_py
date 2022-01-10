#!/usr/bin/env python3

import ssl
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
                conn, addr = self.socket.accept()
                log = f"[{addr[0]}]: connected"
                print(log)
                for user in self.users:
                    user.send(log.encode())
                conn.send(f"Welcome to the server!".encode())
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
                    log = f"[{addr[0]}]: disconnected"
                    print(log)
                    self.users.remove(conn)
                    for user in self.users:
                        user.send(log.encode())
                    conn.close()
                    return
                try:
                    data = data.decode().split('\r\n')
                    header = data[0]
                    body = data[1]
                except IndexError:
                    log = "Wrong request!"
                    print(f"[{addr[0]}]: {log}")
                    conn.send(log.encode())
                    continue
                if header == "message":
                    log = f"{body}"
                    print(f"[{addr[0]}]: {log}")
                    for user in self.users:
                        if user != conn:
                            user.send(f"[{addr[0]}]: {log}".encode())
            conn.close()
        except ConnectionResetError:
            conn = None
            self.users.remove(conn)

if __name__ == "__main__":
    server = Server(serv_addr, serv_port)
    try:
        server.start()
    except KeyboardInterrupt:
        print()
        exit(0)
