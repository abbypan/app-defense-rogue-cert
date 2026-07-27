# app defense rogue cert

# install

    pacman -S certificate-ripper-bin python-pip jdk21-openjdk maven openssl

    pip install -r requirements.txt

    npm install -g eckles
    

# signing

	gen_app_signing_key.sh

	gen_claim_signing_key.sh

	gen_jwt_ClaimSigningKey.py 

	gen_jwt_ServerCertClaim.py server-cert.pem


# proverif

    proverif -lib base.pvl aspin_bgp_hijacking.pv
    proverif -lib base.pvl aspin_dns_hijacking.pv
    proverif -lib base.pvl aspin_mitm.pv

Verify that the ASPin/TLS models, saved ProVerif results, and the protocol
and result tables in `tex/` remain aligned:

    python proverif/check_consistency.py
    
    proverif -lib base.pvl tls_bgp_hijacking.pv 
    proverif -lib base.pvl tls_dns_hijacking.pv
    proverif -lib base.pvl tls_mitm.pv 
