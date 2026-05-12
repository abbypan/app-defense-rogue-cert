#!/usr/bin/python3

import ssl
import sys
import time
from jwcrypto import jwk,jws
from jwcrypto.common import json_encode


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

   issuer = x509_name_to_string(cert_info["issuer"])
   return host, issuer


cert = "my-claim-cert.pem"
with open(cert, "r") as f:
   cert_pem = f.read()
f.closed


pro_header = json_encode({
        "alg": "PS384", 
        "x5c": [ cert_pem ]
        })


priv = "my-claim-key.pem"
with open(priv, "rb") as f:
   priv_pem = f.read()
f.closed
priv_key = jwk.JWK.from_pem(priv_pem, None)
#print(priv_key)


server_cert = sys.argv[1]
host, issuer = read_cert_claim(server_cert)

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

sigf = ("ServerCertClaim.jwt")
f = open(sigf, "w")
f.write(sig)
f.close()
