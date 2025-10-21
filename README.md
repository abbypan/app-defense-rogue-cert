# app_trust_cert

# install

    pacman -S certificate-ripper-bin python-jwcrypto jdk21-openjdk maven openssl

    npm install -g eckles
    


# signing

	./gen_app_signing_key.sh

	./gen_certclaim_signing_key.sh

	./gen_jwt_serverCertClaimSigningKey.py 

	./gen_jwt_serverCertClaim.py appservercert.run.place "CN=E7, O=Let's Encrypt, C=US"
