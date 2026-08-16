#!/usr/bin/env python3

import base64
import hashlib
import json
import os
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

app_public_key_b64 = pem_public_key_der_b64("my-app-pubkey.pem")
app_public_key_der = base64.b64decode(app_public_key_b64)
protected_header = json_encode({
    "alg": algorithm,
    "kid": base64.urlsafe_b64encode(
        hashlib.sha256(app_public_key_der).digest()
    ).rstrip(b"=").decode("ascii"),
})

private_key = jwk.JWK.from_pem(Path("my-app-key.pem").read_bytes(), None)
claim_public_jwk = json.loads(
    Path("my-claim-pubkey.jwk").read_text(encoding="utf-8")
)

issued_at = next_issued_at("ClaimSigningKey.jws")
payload = json_encode({
    "cnf": {"jwk": claim_public_jwk},
    "iat": issued_at,
    "exp": issued_at + ttl_seconds,
})

token = jws.JWS(payload)
token.add_signature(private_key, None, protected_header, None)
Path("ClaimSigningKey.jws").write_text(
    general_jws_serialization(token), encoding="utf-8"
)
