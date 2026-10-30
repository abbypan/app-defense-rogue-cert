#!/usr/bin/env python3
"""Generate concrete CA-migration and signing-key-rotation JWS test vectors."""

import argparse
import base64
import hashlib
import json
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def public_der(path):
    return serialization.load_pem_public_key(path.read_bytes()).public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def header(public_path, algorithm):
    return json_encode({
        "alg": algorithm,
        "kid": b64url(hashlib.sha256(public_der(public_path)).digest()),
    })


def general_jws(payload, signers):
    encoded_payload = json_encode(payload)
    flattened_signatures = []
    for private_path, public_path, algorithm in signers:
        token = jws.JWS(encoded_payload)
        token.add_signature(
            jwk.JWK.from_pem(private_path.read_bytes()),
            None,
            header(public_path, algorithm),
            None,
        )
        flattened = json.loads(token.serialize(compact=False))
        flattened_signatures.append({
            name: flattened[name]
            for name in ("protected", "header", "signature")
            if name in flattened
        })
        encoded = flattened["payload"]
    return json.dumps(
        {"payload": encoded, "signatures": flattened_signatures},
        separators=(",", ":"),
        sort_keys=True,
    )


def decode_payload(path):
    value = json.loads(path.read_text(encoding="utf-8"))
    encoded = value["payload"]
    return json.loads(
        base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    )


def issuer_id(path):
    certificate = x509.load_pem_x509_certificate(path.read_bytes())
    return "sha256:" + b64url(hashlib.sha256(
        certificate.public_bytes(serialization.Encoding.DER)
    ).digest())


def cert_identity(path):
    certificate = x509.load_pem_x509_certificate(path.read_bytes())
    extension = certificate.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value
    sans = [
        str(name.value)
        for name in extension
        if isinstance(name, (x509.DNSName, x509.IPAddress))
    ]
    return certificate.subject.rfc4514_string(), sans


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def wait_metadata(output, values):
    write(output / "schedule.json", json.dumps(values, indent=2, sort_keys=True) + "\n")


def generate_ca_migration(args):
    signing = args.signing_dir
    output = args.output_dir
    current_subject, current_sans = cert_identity(args.current_cert)
    new_subject, new_sans = cert_identity(args.new_cert)
    if (current_subject, current_sans) != (new_subject, new_sans):
        raise SystemExit("CurrentCert and NewCert must use the same Subject/SAN partition")
    existing = decode_payload(signing / "ServerCertClaim.jws")
    iat1 = max(int(time.time()), int(existing["iat"]) + 1)
    iat2 = iat1 + 1
    iat3 = iat2 + args.overlap_seconds
    signer = [(
        signing / "my-claim-key.pem",
        signing / "my-claim-pubkey.pem",
        "ES256",
    )]
    common = {"subject": current_subject, "san": current_sans}
    claims = (
        ("tc-w1-current-only.jws", iat1, iat1 + args.regular_ttl,
         [issuer_id(args.current_ca)]),
        ("tc-w2-overlap.jws", iat2, iat3,
         [issuer_id(args.current_ca), issuer_id(args.new_ca)]),
        ("tc-w3-new-only.jws", iat3, iat3 + args.regular_ttl,
         [issuer_id(args.new_ca)]),
    )
    for name, iat, exp, issuers in claims:
        write(output / name, general_jws(common | {
            "issuer": issuers, "iat": iat, "exp": exp,
        }, signer))
    wait_metadata(output, {
        "w1_iat": iat1,
        "w2_iat": iat2,
        "w2_exp": iat3,
        "w3_iat": iat3,
        "lmax_seconds": args.overlap_seconds,
    })


def generate_claim_key_rotation(args):
    signing = args.signing_dir
    output = args.output_dir
    old_tk = decode_payload(signing / "ClaimSigningKey.primary.jws")
    old_tc = decode_payload(signing / "ServerCertClaim.jws")
    issued_at = max(int(time.time()), int(old_tk["iat"]) + 1, int(old_tc["iat"]) + 1)
    new_key = jwk.JWK.generate(kty="EC", crv="P-256")
    new_private = output / "new-claim-key.pem"
    new_public = output / "new-claim-pubkey.pem"
    output.mkdir(parents=True, exist_ok=True)
    new_private.write_bytes(new_key.export_to_pem(private_key=True, password=None))
    new_public.write_bytes(new_key.export_to_pem())
    claim_jwk = json.loads(new_key.export_public())
    tk_payload = {
        "cnf": {"jwk": claim_jwk},
        "iat": issued_at,
        "exp": issued_at + args.ttl,
    }
    root = [(signing / "my-app-key.pem", signing / "my-app-pubkey.pem", "ES256")]
    write(output / "tk-new-claim-key.jws", general_jws(tk_payload, root))

    source = old_tc
    tc_payload = {
        "subject": source["subject"],
        "san": source["san"],
        "issuer": source["issuer"],
        "iat": issued_at,
        "exp": issued_at + args.ttl,
    }
    write(output / "tc-new-claim-key.jws", general_jws(tc_payload, [
        (new_private, new_public, "ES256")
    ]))
    wait_metadata(output, {"iat": issued_at, "exp": issued_at + args.ttl})


def generate_cross_sign(args):
    signing, fixtures, output = args.signing_dir, args.fixture_dir, args.output_dir
    leaf = x509.load_pem_x509_certificate((fixtures / "leaf.pem").read_bytes())
    direct_a = x509.load_pem_x509_certificate((fixtures / "direct-a.pem").read_bytes())
    direct_b = x509.load_pem_x509_certificate((fixtures / "direct-b.pem").read_bytes())
    leaf.verify_directly_issued_by(direct_a)
    leaf.verify_directly_issued_by(direct_b)
    def spki(certificate):
        return certificate.public_key().public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
    if direct_a.subject != direct_b.subject or spki(direct_a) != spki(direct_b):
        raise ValueError("Cross-sign fixtures must have the same issuer Subject and key")
    previous = decode_payload(signing / "ServerCertClaim.jws")
    iat = max(int(time.time()), int(previous["iat"]) + 1)
    subject, sans = cert_identity(fixtures / "leaf.pem")
    common = {"subject": subject, "san": sans, "exp": iat + args.ttl}
    signer = [(signing / "my-claim-key.pem", signing / "my-claim-pubkey.pem", "ES256")]
    write(output / "tc-incomplete.jws", general_jws(common | {
        "iat": iat, "issuer": [issuer_id(fixtures / "direct-a.pem")],
    }, signer))
    write(output / "tc-complete.jws", general_jws(common | {
        "iat": iat + 1, "issuer": [issuer_id(fixtures / "direct-a.pem"),
                                  issuer_id(fixtures / "direct-b.pem")],
    }, signer))
    wait_metadata(output, {"incomplete_iat": iat, "complete_iat": iat + 1,
                           "exp": iat + args.ttl})


def generate_app_key_rotation(args):
    old_dir = args.old_signing_dir
    new_dir = args.new_signing_dir
    claim_dir = args.claim_signing_dir
    output = args.output_dir
    old_tk = decode_payload(old_dir / "ClaimSigningKey.primary.jws")
    old_tc = decode_payload(claim_dir / "ServerCertClaim.jws")
    iat2 = max(int(time.time()), int(old_tk["iat"]) + 1, int(old_tc["iat"]) + 1)
    iat3 = iat2 + 1
    claim_jwk = json.loads(
        (claim_dir / "my-claim-pubkey.jwk").read_text(encoding="utf-8")
    )
    payload2 = {"cnf": {"jwk": claim_jwk}, "iat": iat2, "exp": iat2 + args.ttl}
    payload3 = {"cnf": {"jwk": claim_jwk}, "iat": iat3, "exp": iat3 + args.ttl}
    old_signer = (old_dir / "my-app-key.pem", old_dir / "my-app-pubkey.pem", "ES256")
    new_signer = (new_dir / "my-app-key.pem", new_dir / "my-app-pubkey.pem", "ES384")
    write(output / "tk-r2-dual.jws", general_jws(payload2, [old_signer, new_signer]))
    write(output / "tk-r3-new-only.jws", general_jws(payload3, [new_signer]))
    tc_payload = {
        "subject": old_tc["subject"],
        "san": old_tc["san"],
        "issuer": old_tc["issuer"],
        "iat": iat2,
        "exp": iat2 + args.ttl,
    }
    write(output / "tc-r2-r3.jws", general_jws(tc_payload, [(
        claim_dir / "my-claim-key.pem",
        claim_dir / "my-claim-pubkey.pem",
        "ES256",
    )]))
    wait_metadata(output, {"r2_iat": iat2, "r3_iat": iat3, "exp": iat2 + args.ttl})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    ca = subparsers.add_parser("ca-migration")
    ca.add_argument("--signing-dir", type=Path, required=True)
    ca.add_argument("--current-cert", type=Path, required=True)
    ca.add_argument("--current-ca", type=Path, required=True)
    ca.add_argument("--new-cert", type=Path, required=True)
    ca.add_argument("--new-ca", type=Path, required=True)
    ca.add_argument("--output-dir", type=Path, required=True)
    ca.add_argument("--overlap-seconds", type=int, default=5)
    ca.add_argument("--regular-ttl", type=int, default=300)
    ca.set_defaults(handler=generate_ca_migration)

    claim = subparsers.add_parser("claim-key-rotation")
    claim.add_argument("--signing-dir", type=Path, required=True)
    claim.add_argument("--output-dir", type=Path, required=True)
    claim.add_argument("--ttl", type=int, default=300)
    claim.set_defaults(handler=generate_claim_key_rotation)

    app = subparsers.add_parser("app-key-rotation")
    app.add_argument("--old-signing-dir", type=Path, required=True)
    app.add_argument("--new-signing-dir", type=Path, required=True)
    app.add_argument("--claim-signing-dir", type=Path, required=True)
    app.add_argument("--output-dir", type=Path, required=True)
    app.add_argument("--ttl", type=int, default=300)
    app.set_defaults(handler=generate_app_key_rotation)

    cross = subparsers.add_parser("cross-sign")
    cross.add_argument("--signing-dir", type=Path, required=True)
    cross.add_argument("--fixture-dir", type=Path, required=True)
    cross.add_argument("--output-dir", type=Path, required=True)
    cross.add_argument("--ttl", type=int, default=300)
    cross.set_defaults(handler=generate_cross_sign)

    args = parser.parse_args()
    if hasattr(args, "overlap_seconds") and args.overlap_seconds < 2:
        parser.error("--overlap-seconds must be at least 2")
    args.handler(args)


if __name__ == "__main__":
    main()
