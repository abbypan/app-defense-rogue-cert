#!/usr/bin/env python3

import base64
import hashlib
import json
import os
import sys
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from issuer_policy import direct_issuer_certificates


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


ISSUER_HASH_ALGORITHMS = {
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
}


def issuer_identifier(issuer_certificate, hash_name):
    """Hash the complete DER certificate of the CA that directly issued the leaf."""
    try:
        digest = ISSUER_HASH_ALGORITHMS[hash_name](
            issuer_certificate.public_bytes(serialization.Encoding.DER)
        ).digest()
    except KeyError as error:
        raise ValueError(f"Unsupported issuer hash algorithm: {hash_name}") from error
    value = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"{hash_name}:{value}"


def read_cert_claim(server_cert, issuer_chains, hash_name):
    certificate = x509.load_pem_x509_certificate(Path(server_cert).read_bytes())
    chain = [
        candidate
        for bundle in issuer_chains
        for candidate in x509.load_pem_x509_certificates(Path(bundle).read_bytes())
    ]
    issuer_certificates = direct_issuer_certificates(certificate, chain)
    try:
        extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        sans = [
            str(name.value)
            for name in extension
            if isinstance(name, (x509.DNSName, x509.IPAddress))
        ]
    except x509.ExtensionNotFound:
        sans = []
    if not sans:
        raise ValueError("The server certificate must contain a DNS or IP SAN")
    return (
        certificate.subject.rfc4514_string(),
        sans,
        [issuer_identifier(issuer_certificate, hash_name)
         for issuer_certificate in issuer_certificates],
    )


def next_issued_at(output_path):
    issued_at = int(time.time())
    path = Path(output_path)
    if not path.exists():
        return issued_at
    try:
        token = json.loads(path.read_text(encoding="utf-8"))
        encoded_payload = token["payload"]
        padding = "=" * (-len(encoded_payload) % 4)
        payload = json.loads(
            base64.urlsafe_b64decode(encoded_payload + padding).decode("utf-8")
        )
        return max(issued_at, int(payload.get("iat", 0)) + 1)
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        return issued_at


def general_jws_serialization(token):
    """Return RFC 7515 General JWS JSON Serialization, even for one signature."""
    flattened = json.loads(token.serialize(compact=False))
    signature = {
        name: flattened[name]
        for name in ("protected", "header", "signature")
        if name in flattened
    }
    return json.dumps(
        {"payload": flattened["payload"], "signatures": [signature]},
        separators=(",", ":"),
        sort_keys=True,
    )


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
})

private_key = jwk.JWK.from_pem(Path("my-claim-key.pem").read_bytes(), None)
issuer_hash_name = os.environ.get("ASPIN_ISSUER_HASH", "sha256").lower()
if len(sys.argv) < 3:
    raise SystemExit("Usage: gen_jws_ServerCertClaim.py LEAF CHAIN [ALTERNATE_CHAIN ...]")
subject, sans, issuers = read_cert_claim(sys.argv[1], sys.argv[2:], issuer_hash_name)

issued_at = next_issued_at("ServerCertClaim.jws")
payload = json_encode({
    "subject": subject,
    "san": sans,
    "issuer": issuers,
    "iat": issued_at,
    "exp": issued_at + ttl_seconds,
})

token = jws.JWS(payload)
token.add_signature(private_key, None, protected_header, None)
Path("ServerCertClaim.jws").write_text(
    general_jws_serialization(token), encoding="utf-8"
)
