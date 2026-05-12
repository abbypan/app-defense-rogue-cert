keytool -genkey -v -keystore my-claim-key.keystore -alias my_cs -keyalg EC -groupname secp256r1 -validity 10000 -dname "CN=CS, OU=Dev, O=MyCompany, L=City, ST=State, C=CN"

openssl pkcs12 -in my-claim-key.keystore -nocerts -nodes -out my-claim-key.pem

#keytool -exportcert -alias my_cs -keystore my-claim-key.keystore -storetype PKCS12 -storepass somepwd -rfc -file my-claim-cert.pem
keytool -exportcert -alias my_cs -keystore my-claim-key.keystore -storetype PKCS12  -rfc -file my-claim-cert.pem

openssl x509 -in my-claim-cert.pem -pubkey -noout > my-claim-pubkey.pem

eckles my-claim-pubkey.pem > my-claim-pubkey.jwk
