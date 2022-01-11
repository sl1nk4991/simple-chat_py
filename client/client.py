#!/usr/bin/env python3

import ssl
import sys
import socket
import argparse
import threading
from os import system
from binascii import Error
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes

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
            if not self.args.inp and not self.args.base64:
                key = getkey(self.salt)
            else:
                try:
                    passphrase = input("Secret passphrase: ")
                except (KeyboardInterrupt, SystemExit):
                    print()
                    exit(0)
                if self.args.inp:
                    f = open(self.args.inp, "rb")
                    encrypted = f.read()
                    f.close()
                elif self.args.base64:
                    try:
                        encrypted = b64decode(self.args.base64)
                    except Error:
                        print("Wrong key!")
                        exit(1)
                try:
                    key = scrypt(passphrase, encrypted[:16], 32, N=2**20, r=8, p=1)
                    cipher = AES.new(key, AES.MODE_EAX, encrypted[16:32])
                    key = cipher.decrypt_and_verify(encrypted[48:], encrypted[32:48])
                except ValueError:
                    print("Wrong passphrase!")
                    exit(1)
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
                decrypted = decrypt(b64decode(message.encode()), key).decode()
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
                encrypted = b64encode(encrypt(userInput.encode(), key))
                self.socket.send("message\r\n".encode() + encrypted)
                prefix = "[ENC]"
            system("clear")
            self.msglog += f"{prefix}[Me]: {userInput}\n"
            print(f"{self.msglog}") 

def getkey(salt):
    try:
        passphrase = input("Enter pre-shared passphrase: ").encode()
    except (KeyboardInterrupt, SystemExit):
        print()
        exit(0)
    key = scrypt(passphrase, salt, 32, N=2**18, r=8, p=1)
    return key

def encrypt(data: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # Sizes(bytes)
    # Nonce: 16, Tag: 16, Ciphertext: -
    encrypted = cipher.nonce + tag + ciphertext
    return encrypted

def decrypt(data: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_EAX, nonce=data[:16])
    decrypted = cipher.decrypt_and_verify(data[32:], data[16:32])
    return decrypted

if __name__ == "__main__":
    parser = argparse.ArgumentParser(usage=f"{sys.argv[0]} [options]")
    parser.add_argument("-s", "--symmetric", action="store_true", 
            help="Use symmetric encryption with pre-shared passphrase"\
                    "(Key derivation function: scrypt, Key size: 256 bits, "\
                    "Encrypt cipher: AES, Mode: EAX)")
    parser.add_argument("-g", "--generate", action="store_true",
            help="Generate key, encrypt and save to output(default is key.bin)")
    parser.add_argument("-i", "--inp", action="store", metavar="inkey",
            help="Input key")
    parser.add_argument("-b", "--base64", action="store", metavar="base64",
            help="Input key with argument")
    parser.add_argument("-o", "--out", action="store", metavar="outkey",
            help="Output key")
    args = parser.parse_args()

    if args.generate:
        try:
            passphrase = input("Secret passphrase: ")
        except (KeyboardInterrupt, SystemExit):
            print()
            exit(0)
        nestedkey =  get_random_bytes(32)
        salt = get_random_bytes(16)
        key = scrypt(passphrase, salt, 32, N=2**20, r=8, p=1)
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(nestedkey)
        if not args.out:
            args.out = "key.bin"
        f = open(args.out, "wb")
        for x in (salt, cipher.nonce, tag, ciphertext):
            f.write(x)
        f.close()
        print("Encrypted key: "\
                f"{b64encode(salt + cipher.nonce + tag + ciphertext).decode()}")
        print(f"Encrypted key writed to {args.out}")
        exit(0)
    client = Client(serv_addr, serv_port, args, salt)
    client.start()
