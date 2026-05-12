#!/bin/bash

keytool -genkey -v -keystore my-dcp-key.keystore -alias my_dcp -keyalg EC -groupname secp256r1 -validity 10000 -dname "CN=DCP, OU=Dev, O=MyCompany, L=City, ST=State, C=CN"

openssl pkcs12 -in my-dcp-key.keystore -nocerts -nodes -out my-dcp-key.pem

#keytool -exportcert -alias my_dcp -keystore my-dcp-key.keystore -storetype PKCS12 -storepass somepwd -rfc -file my-dcp-cert.pem
keytool -exportcert -alias my_dcp -keystore my-dcp-key.keystore -storetype PKCS12  -rfc -file my-dcp-cert.pem

openssl x509 -in my-dcp-cert.pem -pubkey -noout > my-dcp-pubkey.pem

eckles my-dcp-pubkey.pem > my-dcp-pubkey.jwk
