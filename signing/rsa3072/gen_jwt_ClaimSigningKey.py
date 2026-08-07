#!/usr/bin/python3

import base64
import sys
import time
from jwcrypto import jwk,jws
from jwcrypto.common import json_encode

def get_pubkey_der_b64(pubkey_pem_path):
    with open(pubkey_pem_path, "r") as f:
        pem = f.read()
    return "".join([l.strip() for l in pem.splitlines() if l.strip() and not l.startswith("-----")])

app_pubkey_b64 = get_pubkey_der_b64("my-app-pubkey.pem")

pro_header = json_encode({
        "alg": "PS256", 
        "pubkey": app_pubkey_b64
        })

priv = "my-app-key.pem"
with open(priv, "rb") as f:
   priv_pem = f.read()
priv_key = jwk.JWK.from_pem(priv_pem, None)

claim_pubkey_b64 = get_pubkey_der_b64("my-claim-pubkey.pem")

now = int(time.time())
payload = json_encode({
        "cnf": {"pubkey": claim_pubkey_b64},
        "iat": now,
        "exp": now + 315360000
        })




jwstoken = jws.JWS(payload)
jwstoken.add_signature(priv_key, None, pro_header, None)
sig = jwstoken.serialize(compact=True)

sigf = "ClaimSigningKey.jwt"
with open(sigf, "w") as f:
   f.write(sig)
