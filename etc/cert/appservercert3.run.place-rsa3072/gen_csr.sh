#!/bin/bash

openssl genrsa -out rsa-privkey.pem 3072

openssl req -new \
	-key rsa-privkey.pem \
	-subj "/C=US/ST=US/L=US/O=US/OU=./CN=appservercert3.run.place/" \
    -addext "subjectAltName = DNS:appservercert3.run.place" \
	-outform pem -out rsa-csr.pem
