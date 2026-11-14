#!/usr/bin/env python3
"""Generate an Android NSC SHA-256 SPKI pin for a server certificate."""

import argparse
import base64
import hashlib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization


DEFAULT_OUTPUT = "my-app-cert-scp-hash.txt"


def certificate_spki_sha256_base64(certificate_path: Path) -> str:
    certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
    spki = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Hash the DER SubjectPublicKeyInfo of the app-server certificate "
            "with SHA-256 and write the Base64 pin accepted by Android NSC."
        )
    )
    parser.add_argument("certificate", type=Path, help="PEM app-server leaf certificate")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path(DEFAULT_OUTPUT),
        help=f"output file (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()

    if not args.certificate.is_file():
        parser.error(f"certificate does not exist: {args.certificate}")

    pin = certificate_spki_sha256_base64(args.certificate)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(pin + "\n", encoding="ascii")
    print(pin)


if __name__ == "__main__":
    main()
