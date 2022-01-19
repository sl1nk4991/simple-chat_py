#!/usr/bin/env python3

import ssl
import sys
import json
import socket
import argparse
import threading
from os import system
from binascii import Error
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import scrypt
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

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
        pub = None
        if self.args.symmetric:
            key = self.symmetricHandler()
        elif self.args.asymmetric:
            key, pub = self.asymmetricHandler()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_verify_locations('ssl/cert.pem')
        self.socket = self.context.wrap_socket(self.socket, 
                server_hostname='localhost')
        try:
            self.socket.connect((self.serv_addr, self.serv_port))
        except ConnectionRefusedError:
            print("Cannot connect to the server!")
            exit(1)
        reciveHandlerThread = threading.Thread(
                target=self.reciveHandler,
                args=(key,pub)
                )
        reciveHandlerThread.start()
        inputHandlerThread = threading.Thread(
                target=self.inputHandler,
                args=(key,pub,),
                daemon=True
                )
        inputHandlerThread.start()
        try:
            reciveHandlerThread.join()
        except (KeyboardInterrupt, SystemExit, EOFError):
            print()
            exit(0)

    def symmetricHandler(self):
        if not self.args.inp:
            try:
                passphrase = input("Enter pre-shared passphrase: ").encode()
            except (KeyboardInterrupt, SystemExit, EOFError):
                print()
                exit(0)
            key = scrypt(passphrase, salt, 32, N=2**18, r=8, p=1)
            return key
        else:
            try:
                passphrase = input("Secret passphrase: ")
            except (KeyboardInterrupt, SystemExit, EOFError):
                print()
                exit(0)
            if self.args.base64:
                try:
                    encrypted = b64decode(self.args.inp)
                except Error:
                    print("Wrong key!")
                    exit(1)
            else:
                f = open(self.args.inp, "rb")
                encrypted = f.read()
                f.close()
            try:
                key = scrypt(passphrase, encrypted[:16], 32, N=2**20, r=8, 
                        p=1)
                cipher = AES.new(key, AES.MODE_EAX, encrypted[16:32])
                return cipher.decrypt_and_verify(encrypted[48:], 
                        encrypted[32:48])
            except ValueError:
                print("Wrong passphrase!")
                exit(1)

    def asymmetricHandler(self):
        try:
            priv = RSA.import_key(open(self.args.inp, "rb").read())
        except ValueError:
            passphrase = input("Decrypt private key with passphrase: ")
            try:
                priv = RSA.import_key(open(self.args.inp, "rb").read(),
                        passphrase=passphrase)
            except ValueError:
                print("Wrong passphrase!")
                exit(1)
        except FileNotFoundError:
            print("No such file or directory!")
            exit(1)
        try:
            pub = RSA.import_key(open(self.args.pubin, "rb").read())
        except (FileNotFoundError, ValueError):
            print("No such public key!")
        return priv, pub

    def reciveHandler(self, key=None, pub=None):
        while True:
            system("clear")
            print(f"{self.msglog}\nEnter: ", end='')
            data = self.socket.recv(2048)
            if not data:
                self.socket.close()
                print()
                return
            data = json.loads(data.decode())
            address = data['address']
            msgType = data['type']
            msg = data['message']
            if msgType == "plain-text" or msgType == "server":
                self.msglog += f"[{address}]: {msg}\n"
            elif data['type'] == "encrypted":
                if not (self.args.symmetric or self.args.asymmetric):
                    self.msglog += f"[{address}]: encrypted\n"
                elif self.args.symmetric:
                    try:
                        decrypted = symDecrypt(b64decode(msg.encode()), 
                                key).decode()
                        self.msglog += f"[ENC][{address}]: {decrypted}\n"
                    except (IndexError, Error, ValueError, KeyError):
                        self.msglog += f"[{address}]: encrypted\n"
                elif self.args.asymmetric:
                    try:
                        decrypted = asymDecrypt(b64decode(msg.encode()), key, 
                                pub).decode()
                        self.msglog += f"[ENC+SIGN][{address}]: {decrypted}\n"
                    except (IndexError, Error, ValueError, KeyError):
                        self.msglog += f"[{address}]: encrypted\n"

    def inputHandler(self, key=None, pub=None):
        while True:
            userInput = input("Enter: ")
            prefix = ''
            if not (self.args.symmetric or self.args.asymmetric):
                msg_type = "plain-text"
                msg = userInput
            elif self.args.symmetric:
                encrypted = b64encode(symEncrypt(userInput.encode(),
                    key)).decode()
                msg_type = "encrypted"
                msg = encrypted
                prefix = "[ENC]"
            elif self.args.asymmetric:
                encrypted = b64encode(asymEncrypt(userInput.encode(), key, 
                    pub)).decode()
                msg_type = "encrypted"
                msg = encrypted
                prefix = "[ENC+SIGN]"
            data = {"header": "message", "type": msg_type, "message": msg}
            self.socket.send(json.dumps(data).encode())
            system("clear")
            self.msglog += f"{prefix}[Me]: {userInput}\n"
            print(f"{self.msglog}") 

def symEncrypt(data: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(pad(data, 16))
    # Sizes(bytes)
    # Nonce: 16, Tag: 16, Ciphertext: -
    encrypted = cipher.nonce + tag + ciphertext
    return encrypted

def asymEncrypt(data: bytes, key: RSA.RsaKey, pub: RSA.RsaKey):
    session_key = get_random_bytes(32)
    cipher_rsa = PKCS1_OAEP.new(pub)
    enc_session_key = cipher_rsa.encrypt(session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    h = SHA256.new(data)
    sign = pss.new(key).sign(h)
    encrypted = enc_session_key + sign + cipher_aes.nonce + tag + ciphertext
    return encrypted

def symDecrypt(data: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_EAX, nonce=data[:16])
    decrypted = unpad(cipher.decrypt_and_verify(data[32:], data[16:32]), 16)
    return decrypted

def asymDecrypt(data: bytes, key: RSA.RsaKey, pub: RSA.RsaKey):
    ks = key.size_in_bytes()
    cipher_rsa = PKCS1_OAEP.new(key)
    session_key = cipher_rsa.decrypt(data[:ks])
    cipher_aes = AES.new(session_key, AES.MODE_EAX, data[ks*2:ks*2+16])
    decrypted = cipher_aes.decrypt_and_verify(data[ks*2+32:], 
            data[ks*2+16:ks*2+32])
    h = SHA256.new(decrypted)
    pss.new(pub).verify(h, data[ks:ks*2])
    return decrypted
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple chat client")
    #usage=f"{sys.argv[0]} [options]")
    cipher = parser.add_mutually_exclusive_group()
    io = parser.add_mutually_exclusive_group()
    cipher.add_argument("-s", "--symmetric", action="store_true", 
            help="Use symmetric encryption with pre-shared passphrase"\
                    "(Key derivation function: scrypt, Key size: 256 bits, "\
                    "Encrypt cipher: AES, Mode: EAX, Block size: 16 bytes")
    cipher.add_argument("-a", "--asymmetric", action="store_true",
            help="Use asymmetric encryption with open key(Algorithm: RSA, "\
                    "Key size: 2048 bits)")
    parser.add_argument("-g", "--generate", action="store_true",
            help="Generate key, encrypt and save to output(defaults: "\
                    "key.bin, private.pem, public.pem)"\
                    " Use -o and -p options to specify how to output key")
    parser.add_argument("-b", "--base64", action="store_true",
            help="Use base64 encoding for i/o")
    io.add_argument("-i", "--inp", action="store", metavar="inkey",
            help="Input key from file. Use with -b key to input as argument")
    io.add_argument("-o", "--out", action="store", metavar="outkey", 
            help="Output key to file. Use with -b key to output as ascii "\
                    "characters")
    parser.add_argument("-u", "--pubin", action="store", metavar="pubin",
            help="Input public key from file")
    parser.add_argument("-p", "--pubout", action="store", metavar="pubout",
            help="Output public key to file")
    args = parser.parse_args()

    if args.pubin and not args.asymmetric:
        parser.error("The -u/--pubin using only with -a/--asymmetric")

    if args.inp and not (args.symmetric or args.asymmetric):
        parser.error("The -i/--inp using only with -s/--symmetric or "\
                "-a/--asymmetric")

    if args.generate and not (args.symmetric or args.asymmetric):
        parser.error("The -g/--generate using only with -s/--symmetric or "\
                "-a/--asymmetric")

    if args.out and not args.generate:
        parser.error("The -o/--out using only with -g/--generate")

    if args.pubout and not args.generate:
        parser.error("The -p/--pubout using only with -g/--generate")

    if args.pubout and not args.asymmetric:
        parser.error("The -p/--pubout using only with -a/--asymmetric")

    if args.generate and args.symmetric:
        try:
            passphrase = input("Secret passphrase: ")
        except (KeyboardInterrupt, SystemExit, EOFError):
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
        print(f"Encrypted key writed to {args.out}")
        if args.base64:
            print("Encrypted key: " + 
                    b64encode(salt + cipher.nonce + tag + 
                        ciphertext).decode())
        exit(0)

    if args.generate and args.asymmetric:
        try:
            passphrase = input("Encrypt private key with passphrase(none "\
                    "for no encryption): ")
        except (KeyboardInterrupt, SystemExit, EOFError):
            print()
            exit(0)
        key = RSA.generate(2048)
        if passphrase:
            private = key.export_key(passphrase=passphrase, pkcs=8,
                    protection="scryptAndAES256-CBC")
        else:
            private = key.export_key()
        public = key.public_key().export_key()
        if not args.out:
            args.out = "private.pem"
        open(args.out, "wb").write(private+b"\n")
        print(f"Private key writed to {args.out}")
        if not args.pubout:
            args.pubout = "public.pem"
        open(args.pubout, "wb").write(public+b"\n")
        print(f"Public key writed to {args.pubout}")
        exit(0)

    if args.base64 and not args.inp:
        parser.error("The -b/--base64 requires -i/--inp or -o/"\
                "--out ")
    if args.asymmetric and not (args.inp and args.pubin):
        parser.error("The -a/--asymmetric requires -i/--inp and -u/--pubin")

    client = Client(serv_addr, serv_port, args, salt)
    client.start()
