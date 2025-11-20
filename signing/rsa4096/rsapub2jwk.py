#!/usr/bin/python3

from cryptography.hazmat.primitives import serialization
from jwcrypto import jwk

import sys

pemf = sys.argv[1]

with open(pemf, "rb") as f:
    pem_data = f.read()

key = jwk.JWK.from_pem(pem_data)

print(key.export(private_key=False))
