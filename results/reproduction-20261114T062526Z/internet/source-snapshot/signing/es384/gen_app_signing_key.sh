#!/bin/bash

keytool -genkey -v -keystore my-app-key.keystore -alias my_app -keyalg EC -groupname secp384r1 -validity 10000 -dname "CN=APP, OU=Dev, O=MyCompany, L=City, ST=State, C=CN" 

openssl pkcs12 -in my-app-key.keystore -nocerts -nodes -out my-app-key.pem
openssl pkcs8 -topk8 -inform PEM -outform DER -nocrypt -in my-app-key.pem -out my-app-key.pk8

keytool -exportcert -alias my_app -keystore my-app-key.keystore -storetype PKCS12 -storepass somepwd -rfc -file my-app-cert.pem 

openssl x509 -in my-app-cert.pem -pubkey -noout > my-app-pubkey.pem 

eckles my-app-pubkey.pem > my-app-pubkey.jwk 
