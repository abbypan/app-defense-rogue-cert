#!/usr/bin/python3

import sys
import time
from jwcrypto import jwk,jws
from jwcrypto.common import json_encode

cert = "my-app-cert.pem"
with open(cert, "r") as f:
   cert_pem = f.read()
f.closed

pro_header = json_encode({
        "alg": "ES256", 
        "x5c": [ cert_pem ]
        })

priv = "my-app-key.pem"
with open(priv, "rb") as f:
   priv_pem = f.read()
f.closed
priv_key = jwk.JWK.from_pem(priv_pem, None)
#print(priv_key)

domf = "my-claim-pubkey.jwk"
with open(domf, "r", encoding="utf-8") as f:
   pk = f.read()
   payload = json_encode({
            "cs_jwk": pk, 
            "exp": int(time.time()) + 518400      # expires in 60 days
        })
f.closed


jwstoken = jws.JWS(payload)

jwstoken.add_signature(priv_key, 
                       None, #alg
                       pro_header , #protected
                       None,
                       )
sig = jwstoken.serialize(compact=True)
#print(sig)

sigf = ("ClaimSigningKey.jwt")
f = open(sigf, "w")
f.write(sig)
f.close()
