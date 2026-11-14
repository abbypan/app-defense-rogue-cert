#!/usr/bin/env python3
"""Generate compatible-mode T_k rooted in the manifest-declared K_s public key."""

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


def public_key_der(path):
    body = "".join(
        line.strip()
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("-----")
    )
    return base64.b64decode(body)


def next_issued_at(output_path):
    issued_at = int(time.time())
    if not output_path.exists():
        return issued_at
    try:
        token = json.loads(output_path.read_text(encoding="utf-8"))
        encoded_payload = token["payload"]
        payload = json.loads(
            base64.urlsafe_b64decode(
                encoded_payload + "=" * (-len(encoded_payload) % 4)
            ).decode("utf-8")
        )
        return max(issued_at, int(payload.get("iat", 0)) + 1)
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        return issued_at


def general_serialization(token):
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
output_path = Path("ClaimSigningKey.compat.jws")
ttl_seconds = int(os.environ.get("ASPIN_TOKEN_TTL_SECONDS", "86400"))
if ttl_seconds <= 0:
    raise ValueError("ASPIN_TOKEN_TTL_SECONDS must be positive")

root_der = public_key_der("my-dcp-pubkey.pem")
protected_header = json_encode({
    "alg": algorithm,
    "kid": base64.urlsafe_b64encode(hashlib.sha256(root_der).digest())
        .rstrip(b"=").decode("ascii"),
})
claim_public_jwk = json.loads(
    Path("my-claim-pubkey.jwk").read_text(encoding="utf-8")
)
issued_at = next_issued_at(output_path)
payload = json_encode({
    "cnf": {"jwk": claim_public_jwk},
    "iat": issued_at,
    "exp": issued_at + ttl_seconds,
})

token = jws.JWS(payload)
token.add_signature(
    jwk.JWK.from_pem(Path("my-dcp-key.pem").read_bytes()),
    None,
    protected_header,
    None,
)
output_path.write_text(general_serialization(token), encoding="utf-8")
