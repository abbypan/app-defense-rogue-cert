#!/bin/bash

keytool -genkey -v -keystore my-dcp-key.keystore -alias my_dcp -keyalg RSA -keysize 3072 -validity 10000 -dname "CN=DCP, OU=Dev, O=MyCompany, L=City, ST=State, C=CN"

openssl pkcs12 -in my-dcp-key.keystore -nocerts -nodes |
  openssl pkcs8 -topk8 -nocrypt -out my-dcp-key.pem

#keytool -exportcert -alias my_dcp -keystore my-dcp-key.keystore -storetype PKCS12 -storepass somepwd -rfc -file my-dcp-cert.pem
keytool -exportcert -alias my_dcp -keystore my-dcp-key.keystore -storetype PKCS12  -rfc -file my-dcp-cert.pem

openssl x509 -in my-dcp-cert.pem -pubkey -noout > my-dcp-pubkey.pem

# Export DER SPKI as hex for NSC DCP and ASPin-compatible manifest roots.
openssl pkey -pubin -in my-dcp-pubkey.pem -outform DER |
  od -An -v -tx1 | tr -d '[:space:]' > my-dcp-pub.txt
printf '\n' >> my-dcp-pub.txt

python3 rsapub2jwk.py my-dcp-pubkey.pem > my-dcp-pubkey.jwk
