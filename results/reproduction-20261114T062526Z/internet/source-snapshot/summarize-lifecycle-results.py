#!/usr/bin/env python3
"""Validate lifecycle probes and write the compact Evaluation result table."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization


TESTS = (
    ("Cross-sign", "incomplete-policy", "cross-sign-incomplete-policy.csv"),
    ("Cross-sign", "incomplete-a", "cross-sign-incomplete-a.csv"),
    ("Cross-sign", "incomplete-b-rejected", "cross-sign-incomplete-b-rejected.csv"),
    ("Cross-sign", "complete-policy", "cross-sign-complete-policy.csv"),
    ("Cross-sign", "complete-a", "cross-sign-complete-a.csv"),
    ("Cross-sign", "complete-b", "cross-sign-complete-b.csv"),
    ("Cross-sign", "same-name-rejected", "cross-sign-same-name-rejected.csv"),
    ("Cross-sign", "padding-rejected", "cross-sign-padding-rejected.csv"),
    ("CA migration", "w1-current-policy", "ca-w1-current-policy.csv"),
    ("CA migration", "w1-current-cert", "ca-w1-current-cert.csv"),
    ("CA migration", "w1-new-cert-rejected", "ca-w1-new-cert-rejected.csv"),
    ("CA migration", "w2-overlap-policy", "ca-w2-overlap-policy.csv"),
    ("CA migration", "w2-current-cert", "ca-w2-current-cert.csv"),
    ("CA migration", "w2-new-cert-authorized", "ca-w2-new-cert-authorized.csv"),
    ("CA migration", "w3-joint-activation", "ca-w3-joint-activation.csv"),
    ("CA migration", "w3-new-cert", "ca-w3-new-cert.csv"),
    ("CA migration", "w3-current-cert-rejected", "ca-w3-current-cert-rejected.csv"),
    ("Claim-key rotation", "r1-old-pair", "claim-key-r1-old.csv"),
    (
        "Claim-key rotation",
        "old-tk-new-tc-rejected",
        "claim-key-old-tk-new-tc-rejected.csv",
    ),
    (
        "Claim-key rotation",
        "new-tk-old-tc-rejected",
        "claim-key-new-tk-old-tc-rejected.csv",
    ),
    ("Claim-key rotation", "r2-new-pair", "claim-key-r2-new.csv"),
    (
        "Claim-key rotation",
        "r1-replay-rejected",
        "claim-key-r1-replay-rejected.csv",
    ),
    ("App-key rotation", "r1-old-key", "app-key-r1-old.csv"),
    ("App-key rotation", "r2-dual-signature", "app-key-r2-dual.csv"),
    ("App-key rotation", "r3-new-key-only", "app-key-r3-new-only.csv"),
    (
        "App-key rotation",
        "r2-replay-rejected",
        "app-key-r2-replay-rejected.csv",
    ),
)


def certificate_id(path):
    certificate = x509.load_pem_x509_certificate(path.read_bytes())
    digest = hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).digest()
    return "sha256:" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def validate_cross_sign(rows, filename, root):
    if filename in ("cross-sign-incomplete-policy.csv", "cross-sign-complete-policy.csv"):
        return
    variants = {
        "cross-sign-incomplete-a.csv": ("direct-a.pem", True),
        "cross-sign-incomplete-b-rejected.csv": ("direct-b.pem", False),
        "cross-sign-complete-a.csv": ("direct-a.pem", True),
        "cross-sign-complete-b.csv": ("direct-b.pem", True),
        "cross-sign-same-name-rejected.csv": ("rogue-direct.pem", False),
        "cross-sign-padding-rejected.csv": ("rogue-direct.pem", False),
    }
    fixture = root / "artifacts" / "cross-sign"
    direct, accepted = variants[filename]
    expected_issuer = certificate_id(fixture / direct)
    expected_leaf = certificate_id(fixture / ("rogue-leaf.pem" if direct == "rogue-direct.pem" else "leaf.pem"))
    if not rows or [row.get("Attempt") for row in rows] != [str(i) for i in range(len(rows))]:
        raise ValueError(f"{filename}: missing or duplicate cross-sign attempts")
    for row in rows:
        expected = dict(Native_Valid="true", Selected_Issuer=expected_issuer,
            Leaf_Digest=expected_leaf, Policy_Checked="true", Result="PASS",
            Accepted=str(accepted).lower(), App_Request_Sent=str(accepted).lower(),
            Policy_Rejected=str(not accepted).lower())
        if filename == "cross-sign-padding-rejected.csv":
            expected["Extra_Seen"] = "true"
        if any(row.get(field) != value for field, value in expected.items()):
            raise ValueError(f"{filename}: native-path or issuer-decision evidence is inconsistent")


def validate_cross_sign_policies(root):
    fixture = root / "artifacts" / "cross-sign"
    a, b = (certificate_id(fixture / name) for name in ("direct-a.pem", "direct-b.pem"))
    if a == b:
        raise ValueError("Cross-sign certificates must have distinct DER identifiers")
    for name, expected in (("tc-incomplete.jws", {a}), ("tc-complete.jws", {a, b})):
        encoded = json.loads((fixture / name).read_text())["payload"]
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if len(payload["issuer"]) != len(expected) or set(payload["issuer"]) != expected:
            raise ValueError(f"{name}: unexpected cross-sign IssuerSet")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results_dir", type=Path)
    args = parser.parse_args()
    root = args.results_dir.resolve()
    if not root.is_dir():
        raise SystemExit(f"Not a lifecycle result directory: {root}")

    summary = []
    cross_sign_counts = set()
    for category, test, filename in TESTS:
        path = root / filename
        if not path.is_file():
            raise SystemExit(f"Missing lifecycle result: {path}")
        with path.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
        if not rows or any(row.get("Result") != "PASS" for row in rows):
            raise SystemExit(f"{path}: missing rows or non-PASS result")
        if category == "Cross-sign":
            validate_cross_sign(rows, filename, root)
            if "Selected_Issuer" in rows[0]:
                cross_sign_counts.add(len(rows))
        summary.append(
            {
                "Category": category,
                "Test": test,
                "Checks": str(len(rows)),
                "Result": "PASS",
            }
        )

    if len(cross_sign_counts) != 1:
        raise SystemExit("Cross-sign cases must have identical nonzero iteration counts")
    validate_cross_sign_policies(root)
    output = root / "table_lifecycle_transitions.csv"
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=("Category", "Test", "Checks", "Result"),
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(summary)
    print(f"Validated {len(summary)} lifecycle transitions and wrote {output}")


if __name__ == "__main__":
    main()
