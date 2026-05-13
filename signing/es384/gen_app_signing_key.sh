#!/bin/bash

keytool -genkey -v -keystore my-app-key.keystore -alias my_app -keyalg EC -groupname secp384r1 -validity 10000 -dname "CN=APP, OU=Dev, O=MyCompany, L=City, ST=State, C=CN" 

openssl pkcs12 -in my-app-key.keystore -nocerts -nodes |
  openssl pkcs8 -topk8 -nocrypt -out my-app-key.pem

keytool -exportcert -alias my_app -keystore my-app-key.keystore -storetype PKCS12 -storepass somepwd -rfc -file my-app-cert.pem 

openssl x509 -in my-app-cert.pem -pubkey -noout > my-app-pubkey.pem 

eckles my-app-pubkey.pem > my-app-pubkey.jwk 
