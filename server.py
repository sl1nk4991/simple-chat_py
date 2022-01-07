#!/usr/bin/env python3

import ssl
import socket
import threading

class Server():
    def __init__(self, serv_addr, serv_port):
        self.socket = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
                )
        self.socket.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_REUSEADDR,
                1
                )
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain('ssl/server.pem', 'ssl/server.key')
        self.socket = self.context.wrap_socket(self.socket, server_side=True)
        self.serv_addr = serv_addr
        self.serv_port = serv_port
        self.users = []

    def start(self):
        self.socket.bind((self.serv_addr, self.serv_port))
        self.socket.listen()
        print(f"Server is listening")
        self.connectionHandler()

    def connectionHandler(self):
        while True:
            conn, addr = self.socket.accept()
            tlog = f"[{addr[0]}]: connected!"
            print(tlog)
            for user in self.users:
                user.send(tlog.encode('utf-8'))
            self.users.append(conn)
            #self.responseHandler(conn, addr)
            responseThread = threading.Thread(
                    target=self.responseHandler,
                    args=(conn,addr,)
                    )
            responseThread.start()

    def responseHandler(self, conn, addr):
        while True:
            data = conn.recv(2048)
            if not data:
                tlog = f"[{addr[0]}]: disconnected!"
                print(tlog)
                self.users.remove(conn)
                for user in self.users:
                    user.send(tlog.encode('utf-8'))
                conn.close()
                return

            tlog = f"[{addr[0]}]: {data.decode('utf-8')}"
            print(tlog)
            for user in self.users:
                if user != conn:
                    user.send(tlog.encode('utf-8'))
                elif user == conn:
                    stlog = f"[You]: {data.decode('utf-8')}"
                    user.send(stlog.encode('utf-8'))

if __name__ == '__main__':
    serv_addr = '127.0.0.1'
    serv_port = 60000
    server = Server(serv_addr, serv_port)
    server.start()

