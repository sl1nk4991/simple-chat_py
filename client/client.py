#!/usr/bin/env python3

import ssl
import socket
import argparse
import threading
from os import system
from binascii import Error
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from base64 import b64encode, b64decode

serv_addr = '127.0.0.1'
serv_port = 60000

# Recommended to change some times salt
# This value needed be synchronized with your companion
salt = b'1passphrasesalt1'

class Client:
    def __init__(self, serv_addr, serv_port, args, salt):
        self.serv_addr = serv_addr
        self.serv_port = serv_port
        self.args = args
        self.salt = salt
        self.msglog = ''

    def start(self):
        key = None
        if self.args.symmetric:
            key = self.getkey()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_verify_locations('ssl/cert.pem')
        self.socket = self.context.wrap_socket(self.socket, 
                server_hostname='localhost')
        self.socket.connect((self.serv_addr, self.serv_port))
        reciveHandlerThread = threading.Thread(
                target=self.reciveHandler,
                args=(key,)
                )
        reciveHandlerThread.start()
        inputHandlerThread = threading.Thread(
                target=self.inputHandler,
                args=(key,),
                daemon=True
                )
        inputHandlerThread.start()
        try:
            reciveHandlerThread.join()
        except (KeyboardInterrupt, SystemExit):
            print()
            exit(0)

    def getkey(self):
        try:
            passphrase = input("Enter pre-shared passphrase: ").encode()
        except (KeyboardInterrupt, SystemExit):
            print()
            exit(0)
        key = scrypt(passphrase, self.salt, 32, N=2**18, r=8, p=1)
        return key

    def encrypt(self, data: bytes, key: bytes):
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        # Sizes(bytes)
        # Nonce: 16, Tag: 16, Ciphertext: -
        encrypted = cipher.nonce + tag + ciphertext
        return encrypted

    def decrypt(self, data: bytes, key: bytes):
        cipher = AES.new(key, AES.MODE_EAX, nonce=data[:16])
        decrypted = cipher.decrypt_and_verify(data[32:], data[16:32])
        return decrypted

    def reciveHandler(self, key=None):
        while True:
            system("clear")
            print(f"{self.msglog}\nEnter: ", end='')
            data = self.socket.recv(2048)
            if not data:
                self.socket.close()
                print()
                return
            if not self.args.symmetric:
                self.msglog += data.decode() + "\n"
                continue
            try:
                user = data.decode().split(': ')[0]
                message = data.decode().split(': ')[1]
                decrypted = self.decrypt(b64decode(message.encode()), key).decode()
                self.msglog += f"[ENC]{user}: {decrypted}\n"
            except (IndexError, Error, ValueError, KeyError):
                self.msglog += data.decode() + "\n"
                continue

    def inputHandler(self, key=None):
        while True:
            userInput = input("Enter: ")
            prefix = ''
            if not self.args.symmetric:
                self.socket.send("message\r\n".encode() + userInput.encode())
            else:
                encrypted = b64encode(self.encrypt(userInput.encode(), key))
                self.socket.send("message\r\n".encode() + encrypted)
                prefix = "[ENC]"
            system("clear")
            self.msglog += f"{prefix}[Me]: {userInput}\n"
            print(f"{self.msglog}") 

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--symmetric", action="store_true", 
            help="Use symmetric encryption with pre-shared key"\
                    "(Key derivation function: scrypt, Key size: 256 bits, "\
                    "Encrypt cipher: AES, Mode: EAX)")
    args = parser.parse_args()

    client = Client(serv_addr, serv_port, args, salt)
    client.start()
