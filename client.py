#!/usr/bin/env python3

import ssl
import socket
import threading
from os import system

class Client():
    def __init__(self, serv_addr, serv_port):
        self.socket = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
                )
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_verify_locations('ssl/server.pem')
        self.socket = self.context.wrap_socket(self.socket, server_hostname='localhost')
        self.serv_addr = serv_addr
        self.serv_port = serv_port
        self.msglog = ''

    def start(self):
        self.socket.connect((self.serv_addr, self.serv_port))
        requestThread = threading.Thread(
                target=self.requestHandler
                )
        requestThread.start()
        self.reciveHandler()


    def requestHandler(self):
        while True:
            userInput = input()
            self.socket.send(userInput.encode('utf-8'))

    def reciveHandler(self):
        while True:
            system("clear")
            print(f"{self.msglog}\n[You]: ", end="")
            data = self.socket.recv(2048)
            self.msglog += f"{data.decode('utf-8')}\n"

if __name__ == '__main__':
    serv_addr = '127.0.0.1'
    serv_port = 60000
    client = Client(serv_addr, serv_port)
    client.start()
