#!/usr/bin/python

import sys
from jwcrypto import jwk,jws
from jwcrypto.common import json_encode

domf = sys.argv[1]

cert = "attester/t.crt"
with open(cert, "r") as f:
   cert_pem = f.read()
f.closed

header = json_encode({
        "alg": "ES256", 
        "x5c": cert_pem
        })


priv = "attester/t_priv.pem"
with open(priv, "rb") as f:
   priv_pem = f.read()
f.closed
priv_key = jwk.JWK.from_pem(priv_pem, None)
#print(priv_key)


with open(domf, "rb") as f:
   payload = f.read()
f.closed

jwstoken = jws.JWS(payload)

jwstoken.add_signature(priv_key, 
                       None, #alg
                       None, #protected
                       header 
                       )
sig = jwstoken.serialize()
#print(sig)

sigf = (domf+".sig")
f = open(sigf, "w")
f.write(sig)
f.close()
