#!/bin/bash
set -euo pipefail

domain="${1:-somedomain.com}"
email="${2:-somemail@gmail.com}"
prefix="${3:-real}"
webdir="${4:-/var/www/$domain}"

csr="${prefix}-csr.pem"

certbot certonly --non-interactive --webroot \
	-w "$webdir" \
	-d "$domain" \
	--email "$email" \
	--csr "$csr" \
	--agree-tos >> cert.log 2>&1

mv 0000_cert.pem "${prefix}-cert.pem"
mv 0000_chain.pem "${prefix}-chain.pem"
mv 0001_chain.pem "${prefix}-fullchain.pem"
