#!/usr/bin/env python3

import re
import cpm
import ssl
import socket
import binascii
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

    def start(self, key):
        self.socket.connect((self.serv_addr, self.serv_port))
        requestThread = threading.Thread(
                target=self.requestHandler,
                args=(key,)
                )
        requestThread.start()
        self.reciveHandler()


    def requestHandler(self, key):
        while True:
            userInput = input()
            encypted = cpm.aeseax.encrypt(userInput, key)
            self.socket.send(encypted)

    def reciveHandler(self):
        while True:
            system("clear")
            print(f"{self.msglog}\n[You]: ", end="")
            data = self.socket.recv(2048).decode('utf-8')
            data = re.split(": ", data)
            try:
                decrypted = cpm.aeseax.decrypt(cpm.a2b(data[1]), key)
                self.msglog += f"{data[0]}: {decrypted.decode()}\n"
            except binascii.Error:
                decrypted = data[1]
                self.msglog += f"{data[0]}: {data[1]}\n"


if __name__ == '__main__':
    f = open("key.bin", "rb")
    key = f.read()
    serv_addr = '127.0.0.1'
    serv_port = 60000
    client = Client(serv_addr, serv_port)
    client.start(key)
