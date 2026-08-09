#!/usr/bin/env python3

import base64
import hashlib
import json
import os
import ssl
import sys
import time
from pathlib import Path

from jwcrypto import jwk, jws
from jwcrypto.common import json_encode


ALGORITHMS = {
    "es256": "ES256",
    "es384": "ES384",
    "rsa3072": "PS256",
    "rsa4096": "PS384",
}


def pem_public_key_der_b64(path):
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return "".join(
        line.strip()
        for line in lines
        if line.strip() and not line.startswith("-----")
    )


def x509_name_to_string(name):
    name_map = {
        "commonName": "CN",
        "countryName": "C",
        "localityName": "L",
        "organizationName": "O",
        "organizationalUnitName": "OU",
        "stateOrProvinceName": "ST",
    }
    return ", ".join(
        name_map.get(key, key) + "=" + value
        for rdn in reversed(name)
        for key, value in rdn
    )


def read_cert_claim(server_cert):
    cert_info = ssl._ssl._test_decode_cert(server_cert)
    sans = [
        value
        for san_type, value in cert_info.get("subjectAltName", [])
        if san_type == "DNS"
    ]
    if not sans:
        raise ValueError("The server certificate must contain at least one DNS SAN")
    return (
        x509_name_to_string(cert_info["subject"]),
        sans,
        x509_name_to_string(cert_info["issuer"]),
    )


def next_issued_at(output_path):
    issued_at = int(time.time())
    path = Path(output_path)
    if not path.exists():
        return issued_at
    try:
        token = path.read_text(encoding="utf-8").strip()
        encoded_payload = token.split(".")[1]
        padding = "=" * (-len(encoded_payload) % 4)
        payload = json.loads(
            base64.urlsafe_b64decode(encoded_payload + padding).decode("utf-8")
        )
        return max(issued_at, int(payload.get("iat", 0)) + 1)
    except (IndexError, ValueError, TypeError, json.JSONDecodeError):
        return issued_at


variant = Path.cwd().name
algorithm = ALGORITHMS[variant]
ttl_seconds = int(os.environ.get("ASPIN_TOKEN_TTL_SECONDS", "86400"))
if ttl_seconds <= 0:
    raise ValueError("ASPIN_TOKEN_TTL_SECONDS must be positive")

claim_public_key_b64 = pem_public_key_der_b64("my-claim-pubkey.pem")
claim_public_key_der = base64.b64decode(claim_public_key_b64)
protected_header = json_encode({
    "alg": algorithm,
    "kid": base64.urlsafe_b64encode(
        hashlib.sha256(claim_public_key_der).digest()
    ).rstrip(b"=").decode("ascii"),
    "pubkey": claim_public_key_b64,
})

private_key = jwk.JWK.from_pem(Path("my-claim-key.pem").read_bytes(), None)
subject, sans, issuer = read_cert_claim(sys.argv[1])

issued_at = next_issued_at("ServerCertClaim.jwt")
payload = json_encode({
    "subject": subject,
    "san": sans,
    "issuer": issuer,
    "iat": issued_at,
    "exp": issued_at + ttl_seconds,
})

token = jws.JWS(payload)
token.add_signature(private_key, None, protected_header, None)
Path("ServerCertClaim.jwt").write_text(
    token.serialize(compact=True), encoding="utf-8"
)
