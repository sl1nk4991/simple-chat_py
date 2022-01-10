simple-chat_py
==============
Simple chat writen in python

Requirements
------------
* OpenSSL
* PyCryptodome


Installation
------------

Create virtual environment with:
```console
python -m venv env
```

Go to virtual environment:
```console
source env/bin/activate
```

Install requirements with:
```console
pip install -r requirements.txt
```

Usage
-----
At first you need generate certificate:
```console
cd server/ssl
./gencert.sh
```

Than copy server certificate to client:
```console
cp server/ssl/cert.pem client/ssl/
```

Run server with:
```console
cd server
./server.py
```

And now run client with:
```console
cd client
./client.py
```

Usage with symmetric encryption
-------------------------------

Start client with symmetric option:
```console
cd client
./client.py -s
```

Troubleshooting
---------------


[Why does `strxor` raise `TypeError: argument 2 must be bytes, not bytearray`?](https://www.pycryptodome.org/en/latest/src/faq.html#why-does-strxor-raise-typeerror-argument-2-must-be-bytes-not-bytearray)
