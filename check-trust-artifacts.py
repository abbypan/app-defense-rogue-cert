#!/usr/bin/env python3
"""Validate generated ASPin artifacts against the token format in the paper."""

import argparse
import base64
import hashlib
import ipaddress
import json
import re
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from jwcrypto import jwk, jws


ALGORITHMS = {
    "es256": "ES256",
    "es384": "ES384",
    "rsa3072": "PS256",
    "rsa4096": "PS384",
}
ISSUER_ID = re.compile(r"^(sha256|sha384):([A-Za-z0-9_-]+)$")
ISSUER_DIGEST_LENGTHS = {"sha256": 32, "sha384": 48}


def b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def decode_general(token_path):
    token = token_path.read_text(encoding="utf-8").strip()
    value = json.loads(token)
    require_exact_keys(value, ("payload", "signatures"), f"{token_path} JWS")
    signatures = value["signatures"]
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise ValueError(
            f"{token_path}: ordinary publication requires one General JWS signature"
        )
    signature = signatures[0]
    require_exact_keys(
        signature, ("protected", "signature"), f"{token_path} JWS signature"
    )
    return (
        token,
        json.loads(b64url_decode(signature["protected"])),
        json.loads(b64url_decode(value["payload"])),
    )


def public_der(pem_path):
    key = serialization.load_pem_public_key(pem_path.read_bytes())
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def key_id(pem_path):
    return base64.urlsafe_b64encode(hashlib.sha256(public_der(pem_path)).digest()).rstrip(
        b"="
    ).decode("ascii")


def canonical_public_jwk(value):
    return json.loads(jwk.JWK(**value).export_public())


def verify_jws(token, public_key_path):
    verifier = jws.JWS()
    verifier.deserialize(token)
    verifier.verify(jwk.JWK.from_pem(public_key_path.read_bytes()))


def require_exact_keys(value, expected, label):
    actual = set(value)
    expected = set(expected)
    if actual != expected:
        raise ValueError(
            f"{label}: fields are {sorted(actual)}, expected {sorted(expected)}"
        )


def require_interval(payload, label):
    iat = payload.get("iat")
    exp = payload.get("exp")
    if isinstance(iat, bool) or not isinstance(iat, int):
        raise ValueError(f"{label}: iat must be an integer NumericDate")
    if isinstance(exp, bool) or not isinstance(exp, int):
        raise ValueError(f"{label}: exp must be an integer NumericDate")
    if iat >= exp:
        raise ValueError(f"{label}: requires iat < exp")


def certificate_names(certificate):
    try:
        extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        return []
    return [
        str(name.value)
        for name in extension
        if isinstance(name, (x509.DNSName, x509.IPAddress))
    ]


def first_pem_certificate(path):
    certificates = x509.load_pem_x509_certificates(path.read_bytes())
    if not certificates:
        raise ValueError(f"{path}: issuer chain contains no certificate")
    return certificates[0]


def issuer_identifier(issuer_certificate, hash_name="sha256"):
    digest = hashlib.new(
        hash_name,
        issuer_certificate.public_bytes(serialization.Encoding.DER),
    ).digest()
    return (
        hash_name
        + ":"
        + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    )


def validate_issuer_identifier(value, variant):
    if not isinstance(value, str):
        raise ValueError(f"{variant}: IssuerId must be a string")
    match = ISSUER_ID.fullmatch(value)
    if match is None:
        raise ValueError(
            f"{variant}: IssuerId must be hash-name:unpadded-base64url-digest"
        )
    hash_name, encoded = match.groups()
    digest = b64url_decode(encoded)
    if len(digest) != ISSUER_DIGEST_LENGTHS[hash_name]:
        raise ValueError(f"{variant}: {hash_name} IssuerId has the wrong digest length")
    if base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii") != encoded:
        raise ValueError(f"{variant}: IssuerId digest is not canonical base64url")


def validate_variant(repo_root, variant):
    signing_dir = repo_root / "signing" / variant
    server_cert_path = (
        repo_root / "realserver" / "etc" / "cert" / variant / "real-cert.pem"
    )
    issuer_chain_path = (
        repo_root / "realserver" / "etc" / "cert" / variant / "real-chain.pem"
    )
    tk_path = signing_dir / "ClaimSigningKey.jws"
    tc_path = signing_dir / "ServerCertClaim.jws"
    tk, tk_header, tk_payload = decode_general(tk_path)
    tc, tc_header, tc_payload = decode_general(tc_path)

    require_exact_keys(tk_header, ("alg", "kid"), f"{variant} T_k header")
    require_exact_keys(tc_header, ("alg", "kid"), f"{variant} T_c header")
    require_exact_keys(tk_payload, ("cnf", "iat", "exp"), f"{variant} T_k payload")
    require_exact_keys(
        tc_payload,
        ("subject", "san", "issuer", "iat", "exp"),
        f"{variant} T_c payload",
    )
    require_exact_keys(tk_payload["cnf"], ("jwk",), f"{variant} T_k cnf")
    require_interval(tk_payload, f"{variant} T_k")
    require_interval(tc_payload, f"{variant} T_c")

    expected_alg = ALGORITHMS[variant]
    if tk_header["alg"] != expected_alg or tc_header["alg"] != expected_alg:
        raise ValueError(f"{variant}: unexpected JWS alg")
    if tk_header["kid"] != key_id(signing_dir / "my-app-pubkey.pem"):
        raise ValueError(f"{variant}: T_k kid does not identify the app signing key")
    if tc_header["kid"] != key_id(signing_dir / "my-claim-pubkey.pem"):
        raise ValueError(f"{variant}: T_c kid does not identify the delegated claim key")

    expected_claim_jwk = canonical_public_jwk(
        json.loads((signing_dir / "my-claim-pubkey.jwk").read_text(encoding="utf-8"))
    )
    actual_claim_jwk = canonical_public_jwk(tk_payload["cnf"]["jwk"])
    if actual_claim_jwk != expected_claim_jwk:
        raise ValueError(f"{variant}: T_k cnf.jwk does not contain K_cpub")

    verify_jws(tk, signing_dir / "my-app-pubkey.pem")
    verify_jws(tc, signing_dir / "my-claim-pubkey.pem")

    app_certificate = x509.load_pem_x509_certificate(
        (signing_dir / "my-app-cert.pem").read_bytes()
    )
    cert_public_der = app_certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if cert_public_der != public_der(signing_dir / "my-app-pubkey.pem"):
        raise ValueError(f"{variant}: APK certificate and T_k trust anchor differ")

    server_certificate = x509.load_pem_x509_certificate(server_cert_path.read_bytes())
    issuer_certificate = first_pem_certificate(issuer_chain_path)
    if server_certificate.issuer != issuer_certificate.subject:
        raise ValueError(f"{variant}: first chain certificate is not the direct issuer")
    server_certificate.verify_directly_issued_by(issuer_certificate)
    expected_issuer = issuer_identifier(issuer_certificate)
    issuers = tc_payload["issuer"]
    if not isinstance(issuers, list) or not issuers:
        raise ValueError(f"{variant}: T_c issuer must be a non-empty IssuerSet")
    for value in issuers:
        validate_issuer_identifier(value, variant)
    if expected_issuer not in issuers:
        raise ValueError(f"{variant}: T_c omits the server certificate IssuerId")

    sans = tc_payload["san"]
    if not isinstance(sans, list) or not sans or not all(
        isinstance(name, str) and name for name in sans
    ):
        raise ValueError(f"{variant}: T_c SAN must be a non-empty string list")
    expected_sans = certificate_names(server_certificate)
    if sans != expected_sans:
        raise ValueError(f"{variant}: T_c SAN does not match the source certificate")
    if tc_payload["subject"] != server_certificate.subject.rfc4514_string():
        raise ValueError(f"{variant}: T_c Subject does not match the source certificate")

    # Exercise DNS/IP normalization so malformed IP literals cannot be silently
    # emitted as certificate identities.
    for name in sans:
        try:
            ipaddress.ip_address(name)
        except ValueError:
            name.encode("idna")

    print(f"{variant}: ASPin artifacts are structurally and cryptographically valid")


def main():
    repo_root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--alg", action="append", choices=tuple(ALGORITHMS))
    args = parser.parse_args()
    for variant in args.alg or tuple(ALGORITHMS):
        validate_variant(repo_root, variant)


if __name__ == "__main__":
    main()
