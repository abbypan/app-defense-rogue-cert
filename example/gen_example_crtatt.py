#!/usr/bin/python

import sys
from jwcrypto import jwk,jws
from jwcrypto.common import json_encode

cert = "../attester/t.crt"
with open(cert, "r") as f:
   cert_pem = f.read()
f.closed

header = json_encode({
        "alg": "ES256", 
        "x5c": cert_pem
        })


priv = "../attester/t_priv.pem"
with open(priv, "rb") as f:
   priv_pem = f.read()
f.closed
priv_key = jwk.JWK.from_pem(priv_pem, None)
#print(priv_key)

payload = json_encode({
    'attdom': 'www.someatt.com',
    'version': 'v20250325150000',
    'expire': '2025-04-25 15:00:00',
    'refresh': 259200,
    "content": [
        {
            "appid": "com.baidu.xxx", 
            "data" : [ {
                "dom": [ "*.baidu.com" ],
                "cadom": [ "globalsign.com", "! letsencrypt.org" ]
                } ] 
            },
        {
            "appid": "com.alipay.xxx", 
            "data" : [{
                "dom": [ "*.alipay.com" ],
                "cadom": [ "digicert.cn", "digicert.com", "digicert-cn.com", "! letsencrypt.org" ]
                }]
            }, 
        ]
    })
jwstoken = jws.JWS(payload)

jwstoken.add_signature(priv_key, 
                       None, #alg
                       None, #protected
                       header 
                       )
sig = jwstoken.serialize()
#print(sig)

f = open("example.json", "w")
f.write(sig)
f.close()
