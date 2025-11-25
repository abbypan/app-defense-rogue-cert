#!/usr/bin/python3

import sys
import time
from jwcrypto import jwk,jws
from jwcrypto.common import json_encode


cert = "my-cs-cert.pem"
with open(cert, "r") as f:
   cert_pem = f.read()
f.closed


pro_header = json_encode({
        "alg": "PS384", 
        "x5c": [ cert_pem ]
        })


priv = "my-cs-key.pem"
with open(priv, "rb") as f:
   priv_pem = f.read()
f.closed
priv_key = jwk.JWK.from_pem(priv_pem, None)
#print(priv_key)


host = sys.argv[1]
issuer = sys.argv[2]

payload = json_encode({
    "host": host,
    "issuer": issuer, 
    "exp": int(time.time()) + 518400      # expires in 60 days
    })

jwstoken = jws.JWS(payload)

jwstoken.add_signature(priv_key, 
                       None, #alg
                       pro_header , #protected
                       None, 
                       )
sig = jwstoken.serialize(compact=True)
#print(sig)

sigf = ("serverCertClaim.jwt")
f = open(sigf, "w")
f.write(sig)
f.close()
