#!/usr/bin/python

import sys
import fcntl
import os
#import profile

from jwcrypto import jwk,jws
from jwcrypto.common import json_decode
from OpenSSL.crypto import (load_certificate, dump_publickey, dump_certificate, X509, X509Name, PKey)
from OpenSSL.crypto import (TYPE_DSA, TYPE_RSA, FILETYPE_PEM, FILETYPE_ASN1)
from Crypto.Util.asn1 import (DerSequence, DerObject)
from Crypto.Hash import SHA256


@profile
def verify(crtatt_js):
    trust_anchor = "301ebf87f32521272334d4bba965d48fccd0d3d999fd9f08c7bf21e7e5c28f54"

    crtatt = json_decode(crtatt_js)
    #print(crtatt)
    crt = load_certificate(FILETYPE_PEM, crtatt["header"]["x5c"])

    subject_pubkey_der = dump_publickey(FILETYPE_ASN1, crt.get_pubkey())
    h = SHA256.new()
    h.update(subject_pubkey_der)
    dgst_spk = h.hexdigest()

    if(dgst_spk==trust_anchor):
        subject_pubkey_pem = dump_publickey(FILETYPE_PEM, crt.get_pubkey())
        pub_key = jwk.JWK.from_pem(subject_pubkey_pem, None)

        jwstoken_v = jws.JWS()
        jwstoken_v.deserialize(crtatt_js)

        res=jwstoken_v.verify(pub_key)

        if(res==None):
            payload_v = jwstoken_v.payload
            return payload_v
     
    return 





crtatt_f = sys.argv[1]
with open(crtatt_f, "r") as f:
   crtatt_js = f.read()
f.closed

payload_v = verify(crtatt_js)

if(payload_v!=None):
        cf = (crtatt_f+".cache")

        fd = os.open(cf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        os.write(fd, payload_v)
        os.close(fd)

        #cache_f = open(cf, "wb")
        #cache_f.write(payload_v)
        #cache_f.closed
