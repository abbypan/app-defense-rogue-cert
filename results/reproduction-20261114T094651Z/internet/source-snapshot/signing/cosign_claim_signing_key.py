#!/usr/bin/env python3
"""Add any number of owner signatures to the same encoded T_k payload."""

import argparse
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode


ALGORITHMS = ("ES256", "ES384", "PS256", "PS384")


def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_canonical(value):
    if not isinstance(value, str):
        raise ValueError("JWS payload must be an encoded string")
    decoded = base64.b64decode(value + "=" * (-len(value) % 4),
                               altchars=b"-_", validate=True)
    if b64url(decoded) != value:
        raise ValueError("JWS payload must use unpadded canonical base64url")
    return decoded


def cosign(token, signers):
    """Preserve existing signatures; each new owner signs the identical payload.

    Existing signatures are not authenticated here: the operator authorizes the
    common delegation by co-signing it. Receivers still verify their own trusted
    context key. No private-key material is included in the returned object.
    """
    general = json.loads(token)
    if not isinstance(general, dict) or set(general) != {"payload", "signatures"}:
        raise ValueError("Input must be General JWS with payload and signatures")
    signatures = general["signatures"]
    if not isinstance(signatures, list) or not signatures:
        raise ValueError("Input must have a non-empty signature array")
    for signature in signatures:
        if not isinstance(signature, dict) or set(signature) != {"protected", "signature"}:
            raise ValueError("Each signature must contain protected and signature")
    payload_bytes = decode_canonical(general["payload"])
    payload = json.loads(payload_bytes)
    if not isinstance(payload, dict) or set(payload) != {"cnf", "iat", "exp"}:
        raise ValueError("T_k payload must contain cnf, iat, and exp")
    if not isinstance(payload["cnf"], dict) or set(payload["cnf"]) != {"jwk"}:
        raise ValueError("T_k must delegate its claim key through cnf.jwk")
    if any(type(payload[name]) is not int or payload[name] <= 0
           for name in ("iat", "exp")) or payload["iat"] >= payload["exp"]:
        raise ValueError("T_k requires positive integral iat < exp")

    for algorithm, private_filename, public_filename in signers:
        if algorithm not in ALGORITHMS:
            raise ValueError("Unsupported ASPin signing algorithm")
        private_pem = Path(private_filename).read_bytes()
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        public_key = serialization.load_pem_public_key(Path(public_filename).read_bytes())
        public_der = public_key.public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        derived_der = private_key.public_key().public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        if public_der != derived_der:
            raise ValueError("Signer private and public keys do not match")
        if algorithm.startswith("ES"):
            curve = "secp256r1" if algorithm == "ES256" else "secp384r1"
            if not isinstance(public_key, ec.EllipticCurvePublicKey) or public_key.curve.name != curve:
                raise ValueError("Signer EC curve does not match the requested algorithm")
        elif not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("PS256/PS384 require an RSA signer")
        protected = json_encode({"alg": algorithm,
            "kid": b64url(hashlib.sha256(public_der).digest())})
        signed = jws.JWS(payload_bytes)
        signed.add_signature(jwk.JWK.from_pem(private_pem), None, protected, None)
        flattened = json.loads(signed.serialize(compact=False))
        if flattened["payload"] != general["payload"]:
            raise ValueError("Co-signing must preserve the original encoded payload")
        signature = {name: flattened[name] for name in ("protected", "signature")}
        general["signatures"].append(signature)
    return json.dumps(general, separators=(",", ":"), sort_keys=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="existing ClaimSigningKey General JWS")
    parser.add_argument("--signer", action="append", nargs=3, required=True,
        metavar=("ALG", "PRIVATE_KEY", "PUBLIC_KEY"),
        help="add one owner signature; repeat for any number of owners")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = cosign(args.input.read_text(encoding="utf-8"), args.signer)
    except (ValueError, TypeError, KeyError, OSError):
        parser.error("Invalid T_k or signer: check the payload, algorithm, and matching key files")
    args.output.write_text(result + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
