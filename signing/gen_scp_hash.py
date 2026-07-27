#!/usr/bin/env python3
"""Generate the SCP SHA-256 pin for an app-server leaf certificate."""

import argparse
import hashlib
import ssl
from pathlib import Path


DEFAULT_OUTPUT = "my-app-cert-scp-hash.txt"


def certificate_sha256_hex(certificate_path: Path) -> str:
    pem = certificate_path.read_text(encoding="ascii")
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha256(der).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Hash the complete DER-encoded app-server leaf certificate with "
            "SHA-256 and write the lowercase hexadecimal SCP pin."
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

    pin = certificate_sha256_hex(args.certificate)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(pin + "\n", encoding="ascii")
    print(pin)


if __name__ == "__main__":
    main()
