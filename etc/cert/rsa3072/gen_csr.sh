#!/bin/bash
set -euo pipefail

domain="${1:-somedomain.com}"
alg="${2:-rsa3072}"
prefix="${3:-real}"

privkey="${prefix}-privkey.pem"
csr="${prefix}-csr.pem"

case "$alg" in
	es256)
		openssl ecparam -genkey -name secp256r1 |
			openssl ec -out "$privkey"
		;;
	es384)
		openssl ecparam -genkey -name secp384r1 |
			openssl ec -out "$privkey"
		;;
	rsa3072)
		openssl genrsa -out "$privkey" 3072
		;;
	rsa4096)
		openssl genrsa -out "$privkey" 4096
		;;
	*)
		echo "Usage: $0 [domain] [es256|es384|rsa3072|rsa4096] [prefix]" >&2
		exit 1
		;;
esac

openssl req -new \
	-key "$privkey" \
	-subj "/C=US/ST=US/L=US/O=US/OU=./CN=${domain}/" \
	-addext "subjectAltName = DNS:${domain}" \
	-outform pem -out "$csr"
