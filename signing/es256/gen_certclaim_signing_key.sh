keytool -genkey -v -keystore my-cs-key.keystore -alias my_cs -keyalg EC -groupname secp256r1 -validity 10000 -dname "CN=CS, OU=Dev, O=MyCompany, L=City, ST=State, C=CN"

openssl pkcs12 -in my-cs-key.keystore -nocerts -nodes -out my-cs-key.pem

#keytool -exportcert -alias my_cs -keystore my-cs-key.keystore -storetype PKCS12 -storepass somepwd -rfc -file my-cs-cert.pem
keytool -exportcert -alias my_cs -keystore my-cs-key.keystore -storetype PKCS12  -rfc -file my-cs-cert.pem

openssl x509 -in my-cs-cert.pem -pubkey -noout > my-cs-pubkey.pem

eckles my-cs-pubkey.pem > my-cs-pubkey.jwk
