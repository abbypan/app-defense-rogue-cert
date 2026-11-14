#!/usr/bin/env python3
"""Independent NSC DCP baseline: directly signed, hostname-bound leaf-SPKI pins.

This is NOT an ASPin delegation or claim. It intentionally has no persistent
rollback state, target-app lookup or lineage merging. Signed iat/exp bound the
in-process cache and permit controlled hot/cold and suppression experiments.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from jwcrypto import jwk, jws

ALGORITHMS = {"es256": "ES256", "es384": "ES384", "rsa3072": "PS256", "rsa4096": "PS384"}


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def generate(root, variant, certificate=None, lifetime=86400, now=None):
    if lifetime <= 0:
        raise ValueError("DCP lifetime must be positive")
    directory = root / "signing" / variant
    certificate = certificate or root / "realserver" / "etc" / "cert" / variant / "real-cert.pem"
    leaf = x509.load_pem_x509_certificate(certificate.read_bytes())
    spki = leaf.public_key().public_bytes(serialization.Encoding.DER,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
    public_key = serialization.load_pem_public_key((directory / "my-dcp-pubkey.pem").read_bytes())
    root_der = public_key.public_bytes(serialization.Encoding.DER,
                                      serialization.PublicFormat.SubjectPublicKeyInfo)
    issued = int(time.time()) if now is None else now
    payload = {"hostname": variant + ".idouzi.top", "pins": ["sha256:" + b64(hashlib.sha256(spki).digest())],
               "iat": issued, "exp": issued + lifetime}
    token = jws.JWS(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    token.add_signature(jwk.JWK.from_pem((directory / "my-dcp-key.pem").read_bytes()),
                        protected=json.dumps({"alg": ALGORITHMS[variant], "kid": b64(hashlib.sha256(root_der).digest())}))
    flat = json.loads(token.serialize(compact=False))
    general = {"payload": flat["payload"], "signatures": [{name: flat[name]
               for name in ("protected", "signature")}]}
    return json.dumps(general, separators=(",", ":"), sort_keys=True) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alg", choices=ALGORITHMS, required=True)
    parser.add_argument("--certificate", type=Path)
    parser.add_argument("--lifetime", type=int, default=86400)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    result = generate(root, args.alg, args.certificate, args.lifetime)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(result, encoding="utf-8")


if __name__ == "__main__":
    main()
