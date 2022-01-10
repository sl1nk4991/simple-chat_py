#!/bin/bash

openssl req -x509 -nodes -days 7 -newkey rsa:4096 -keyout cert.key -out cert.pem -sha512 -config openssl.cnf
