#!/bin/bash
openssl ecparam -genkey -name secp384r1 | \
	openssl ec -out ecc-privkey.pem

openssl req -new \
	-key ecc-privkey.pem \
	-subj "/C=US/ST=US/L=US/O=US/OU=./CN=appservercert.run.place/" \
    -addext "subjectAltName = DNS:appservercert.run.place" \
	-outform pem -out ecc-csr.pem
