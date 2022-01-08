from . import aeseax
from . import aesgcm
from os import urandom
from pbkdf2 import PBKDF2
from binascii import hexlify, unhexlify

def genkey(*passphrase :str):
    if passphrase:
        salt = urandom(8)
        return PBKDF2(passphrase, salt).read(32)
    else:
        return urandom(32)

def b2a(data):
    return hexlify(data).decode()

def a2b(data):
    return unhexlify(data)
