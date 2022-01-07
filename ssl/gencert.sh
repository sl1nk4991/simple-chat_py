#!/bin/bash

openssl req -x509 -new -keyout server.key -nodes -out server.pem -config server.cnf
