# app_trust_cert

# install

    pacman -S certificate-ripper-bin python-pip jdk21-openjdk maven openssl

    pip install -r requirements.txt

    npm install -g eckles
    


# signing

	./gen_app_signing_key.sh

	./gen_claim_signing_key.sh

	./gen_jwt_ClaimSigningKey.py 

	./gen_jwt_ServerCertClaim.py server-cert.pem


# proverif

    proverif -lib base.pvl asproc_bgp_hijacking.pv | tee asproc_bgp_hijacking.log
    proverif -lib base.pvl asproc_dns_hijacking.pv | tee asproc_dns_hijacking.log
    proverif -lib base.pvl asproc_mitm.pv | tee asproc_mitm.log
    
    proverif -lib base.pvl tls_bgp_hijacking.pv | tee tls_bgp_hijacking.log
    proverif -lib base.pvl tls_dns_hijacking.pv | tee tls_dns_hijacking.log
    proverif -lib base.pvl tls_mitm.pv | tee tls_mitm.log
