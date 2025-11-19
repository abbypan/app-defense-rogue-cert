#!/bin/bash
openssl ecparam -genkey -name secp256r1 | \
	openssl ec -out ecc-privkey.pem

openssl req -new \
	-key ecc-privkey.pem \
	-subj "/C=US/ST=US/L=US/O=US/OU=./CN=appservercert2.run.place/" \
    -addext "subjectAltName = DNS:appservercert2.run.place" \
	-outform pem -out ecc-csr.pem
