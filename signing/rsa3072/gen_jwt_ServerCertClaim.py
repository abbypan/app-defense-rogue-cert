#!/usr/bin/python3

import base64
import ssl
import sys
import time
from jwcrypto import jwk,jws
from jwcrypto.common import json_encode


def get_pubkey_der_b64(pubkey_pem_path):
    with open(pubkey_pem_path, "r") as f:
        pem = f.read()
    return "".join([l.strip() for l in pem.splitlines() if l.strip() and not l.startswith("-----")])


def x509_name_to_string(name):
   name_map = {
      "commonName": "CN",
      "countryName": "C",
      "localityName": "L",
      "organizationName": "O",
      "organizationalUnitName": "OU",
      "stateOrProvinceName": "ST",
   }

   attrs = []
   for rdn in reversed(name):
      for key, value in rdn:
         attrs.append(name_map.get(key, key) + "=" + value)

   return ", ".join(attrs)


def read_cert_claim(server_cert):
   cert_info = ssl._ssl._test_decode_cert(server_cert)

   host = None
   for san_type, san_value in cert_info.get("subjectAltName", []):
      if san_type == "DNS":
         host = san_value
         break

   if host is None:
      for rdn in cert_info.get("subject", []):
         for key, value in rdn:
            if key == "commonName":
               host = value
               break
         if host is not None:
            break

   if host is None:
      raise ValueError("Could not read host from certificate SAN or subject CN")

   subject = x509_name_to_string(cert_info["subject"])
   sans = [value for san_type, value in cert_info.get("subjectAltName", [])
           if san_type == "DNS"]
   issuer = x509_name_to_string(cert_info["issuer"])
   return host, subject, sans, issuer


claim_pubkey_b64 = get_pubkey_der_b64("my-claim-pubkey.pem")

pro_header = json_encode({
        "alg": "PS256", 
        "pubkey": claim_pubkey_b64
        })

priv = "my-claim-key.pem"
with open(priv, "rb") as f:
   priv_pem = f.read()
priv_key = jwk.JWK.from_pem(priv_pem, None)

server_cert = sys.argv[1]
host, subject, sans, issuer = read_cert_claim(server_cert)

now = int(time.time())
payload = json_encode({
    "subject": subject,
    "san": sans,
    "issuer": issuer,
    "iat": now,
    "exp": now + 315360000
    })




jwstoken = jws.JWS(payload)
jwstoken.add_signature(priv_key, None, pro_header, None)
sig = jwstoken.serialize(compact=True)

sigf = "ServerCertClaim.jwt"
with open(sigf, "w") as f:
   f.write(sig)
