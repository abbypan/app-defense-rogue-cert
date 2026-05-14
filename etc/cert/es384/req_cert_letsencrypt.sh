#!/bin/bash
set -euo pipefail

domain="${1:-somedomain.com}"
email="${2:-somemail@gmail.com}"
prefix="${3:-real}"
webdir="${4:-/var/www/$domain}"

privkey="${prefix}-privkey.pem"
csr="${prefix}-csr.pem"

certbot certonly --non-interactive --webroot \
	-w "$webdir" \
	-d "$domain" \
	--email "$email" \
	--csr "$csr" \
	--agree-tos >> cert.log 2>&1

mv 0000_cert.pem cert.pem
mv 0000_chain.pem chain.pem
mv 0001_chain.pem fullchain.pem

if [ -f "$privkey" ]; then
	cp "$privkey" privkey.pem
fi
