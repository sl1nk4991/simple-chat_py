#!/bin/bash

openssl req -x509 -nodes -days 7 -newkey rsa:2048 -keyout server.key -out server.pem -sha256 -config openssl.cnf
