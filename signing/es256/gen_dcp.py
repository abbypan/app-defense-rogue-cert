#!/usr/bin/python3

import base64
import re
import sys
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Util.asn1 import DerSequence


def read_pem_file(path, label):
   with open(path, "r") as f:
      pem = f.read()
   f.closed

   match = re.search(
      r"-----BEGIN " + re.escape(label) + r"-----(.*?)-----END " + re.escape(label) + r"-----",
      pem,
      re.S,
   )
   if not match:
      raise ValueError("Could not find PEM block: " + label)

   return base64.b64decode("".join(match.group(1).split()))


def read_subject_pk(cert):
   cert_der = read_pem_file(cert, "CERTIFICATE")
   cert_seq = DerSequence()
   cert_seq.decode(cert_der)

   tbs_seq = DerSequence()
   tbs_seq.decode(cert_seq[0])

   has_version = isinstance(tbs_seq[0], bytes) and tbs_seq[0][0] == 0xa0
   subject_pk_index = 6 if has_version else 5

   return tbs_seq[subject_pk_index]


def sign_subject_pk(dcp_priv, subject_pk):
   dcp_key = ECC.import_key(read_pem_file(dcp_priv, "PRIVATE KEY"))
   signer = DSS.new(dcp_key, "fips-186-3", encoding="der")
   return signer.sign(SHA256.new(subject_pk))


dcp_cert = "my-dcp-cert.pem"
pubf = ("my-dcp-pub.txt")
f = open(pubf, "w")
f.write(read_subject_pk(dcp_cert).hex())
f.close()

dcp_priv = "my-dcp-key.pem"
server_cert = sys.argv[1]
subject_pk = read_subject_pk(server_cert)
sig = sign_subject_pk(dcp_priv, subject_pk)

sigf = ("my-dcp-servercertpin.bin")
f = open(sigf, "wb")
f.write(sig)
f.close()
