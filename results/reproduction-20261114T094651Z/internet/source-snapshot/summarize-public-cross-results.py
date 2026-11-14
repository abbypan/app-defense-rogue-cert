#!/usr/bin/env python3
"""Verify public-CA observations from saved DER paths, JWS and HTTP audits."""
import argparse
import base64
import csv
import importlib.util
import json
import math
import hashlib
from pathlib import Path
import re

from cryptography import x509
from jwcrypto import jwk, jws

import public_cross_protocol as protocol

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("public_cross_audit", ROOT / "run-cross-sign-benchmark.py")
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)


def payload(filename, key):
    value = json.loads(filename.read_text())
    if not isinstance(value.get("signatures"), list) or not value["signatures"]:
        raise ValueError("General JWS signature array required")
    token = jws.JWS(); token.deserialize(json.dumps(value)); token.verify(key)
    return json.loads(token.payload)


def validate_row(row, cell, iterations, fixtures, policy, trusted):
    accept = cell["accepted"]
    provider = "zerossl" if "zerossl" in cell["presentation"] else "le"
    def cert(name): return x509.load_pem_x509_certificate((fixtures / name).read_bytes())
    leaf, issuer = cert(provider + "-leaf.pem"), cert(provider + "-issuer.pem")
    expected = {"Scenario": cell["scenario"], "Mode": cell["mode"], "Native_Valid": "true",
                "Policy_Checked": "true", "Policy_Rejected": str(not accept).lower(),
                "Accepted": str(accept).lower(), "App_Request_Sent": str(accept).lower(),
                "Result": "PASS", "Leaf_Digest": protocol.identifier(leaf),
                "Selected_Issuer": protocol.identifier(issuer)}
    if any(row.get(field) != value for field, value in expected.items()):
        raise ValueError("Native-path/issuer-policy evidence disagrees with expected outcome")
    if set(row["Claim_Issuers"].split(";")) != set(policy["issuer"]):
        raise ValueError("OS claim does not match authenticated issuer set")
    for name in ("Tk_ms", "Tc_ms"):
        value = float(row[name])
        if not math.isfinite(value) or value <= 0: raise ValueError("Missing OS token-refresh evidence")
    selected = [x509.load_der_x509_certificate(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
                for part in row["Validated_Path_DER"].split(";")]
    identifiers = [protocol.identifier(cert) for cert in selected]
    if (len(selected) < 2 or identifiers != row["Validated_Path"].split(";")
            or selected[0] != leaf or selected[1] != issuer):
        raise ValueError("Actual native path DER does not match recorded fingerprints")
    for child, parent in zip(selected, selected[1:]): child.verify_directly_issued_by(parent)
    if identifiers[-1] not in trusted: raise ValueError("Native path does not terminate at an Android system root")
    chain = x509.load_pem_x509_certificates((fixtures / (cell["presentation"] + "-fullchain.pem")).read_bytes())
    if row["Peer_Path"].split(";") != [protocol.identifier(cert) for cert in chain]:
        raise ValueError("Peer certificate input differs from configured public chain")
    padded = "padded" in cell["presentation"]
    if padded:
        if row["Extra_Seen"] != "true" or protocol.identifier(cert("le-issuer.pem")) not in row["Peer_Path"].split(";"):
            raise ValueError("Padded authorized CA was not actually received")
    if not accept and "Direct issuer CA certificate is not authorized by the authenticated ASPin claim" not in row["Error"]:
        raise ValueError("Negative case was not the exact issuer-policy refusal")
    return tuple(identifiers)


def summarize(directory):
    manifest = json.loads((directory / "manifest.json").read_text())
    if (manifest["state"] != "complete" or not manifest.get("restored_app")
            or not manifest.get("endpoint_finalized") or manifest["root_store"] != "Android system only"):
        raise ValueError("Incomplete public-root-only run or cleanup")
    fixtures, count = directory / "artifacts", manifest["iterations"]
    expected = {(mode, name): (presentation, policy, accept) for mode in ("primary", "compatible")
                for name, presentation, policy, accept, padded in protocol.plan()}
    cells = manifest["cells"]
    if len(cells) != len(expected) or {(c["mode"], c["case"]) for c in cells} != set(expected):
        raise ValueError("Missing or duplicate public-CA cells")
    if len({c["scenario"] for c in cells}) != len(cells): raise ValueError("Repeated audit labels")
    # Hash the archived root DER without ASN.1-parsing unrelated legacy anchors
    # (some native stores contain old nonpositive serials). The SELECTED native
    # path, including its root, is still fully parsed and signature-checked.
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----",
                        (fixtures / "android-system-roots.pem").read_bytes())
    trusted = {"sha256:" + base64.urlsafe_b64encode(hashlib.sha256(base64.b64decode(
        re.sub(rb"\s+", b"", block), validate=True)).digest()).rstrip(b"=").decode() for block in blocks}
    if not trusted: raise ValueError("Missing actual Android system root snapshot")
    leaf_a, leaf_b = (x509.load_pem_x509_certificate((fixtures / (name + "-leaf.pem")).read_bytes())
                      for name in ("le", "zerossl"))
    csr = x509.load_pem_x509_csr((fixtures / "server.csr.pem").read_bytes())
    from cryptography.hazmat.primitives import serialization
    requested = csr.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if not csr.is_signature_valid or protocol.public_der(leaf_a) != requested or protocol.public_der(leaf_b) != requested:
        raise ValueError("Two public leaves must match the one actual CSR")
    if leaf_a == leaf_b: raise ValueError("Expected distinct public-CA leaf certificates")
    policies = {}
    for mode in ("primary", "compatible"):
        root = jwk.JWK.from_pem((fixtures / (mode + "-root.pem")).read_bytes())
        tk = payload(directory / (mode + "-key.jws"), root)
        claim_key = jwk.JWK(**tk["cnf"]["jwk"])
        previous_iat = None
        for label, issuers in manifest["certificate_info"]["issuer_sets"].items():
            tc = payload(directory / (mode + "-" + label + ".jws"), claim_key)
            if (set(tc["issuer"]) != set(issuers) or len(tc["issuer"]) != len(issuers)
                    or not tk["iat"] <= tc["iat"] < min(tk["exp"], tc["exp"])
                    or (previous_iat is not None and tc["iat"] <= previous_iat)):
                raise ValueError("Invalid signed issuer set, freshness or publication order")
            if tc["subject"] != leaf_a.subject.rfc4514_string() or tc["san"] != [manifest["hostname"]]:
                raise ValueError("Signed claim names differ from the requested public hostname")
            previous_iat = tc["iat"]
            policies[mode, label] = tc
    summary, observed_paths, accepted, padded_attempts, unattributed = [], set(), 0, 0, 0
    for cell in cells:
        if (cell["presentation"], cell["policy"], cell["accepted"]) != expected[cell["mode"], cell["case"]]:
            raise ValueError("Manifest case does not match protocol")
        name = cell["mode"] + "-" + cell["case"] + ".csv"
        if cell["file"] != name: raise ValueError("Unexpected raw observation filename")
        with (directory / name).open(newline="") as stream: rows = list(csv.DictReader(stream))
        if len(rows) != count or [r["Attempt"] for r in rows] != [str(i) for i in range(count)]:
            raise ValueError("Missing/duplicate measured attempts")
        paths = set()
        for row in rows:
            path = validate_row(row, cell, count, fixtures, policies[cell["mode"], cell["policy"]], trusted)
            paths.add(path); observed_paths.add(path)
        audit = json.loads((directory / name).with_suffix(".audit.json").read_text())
        BASE.audit_requests(audit["tagged"], cell["scenario"], count, cell["accepted"])
        if any(event.get("observation") for event in audit["unattributed"]):
            raise ValueError("Labeled requests cannot be excluded as unattributed")
        unattributed += len(audit["unattributed"])
        if cell["accepted"]: accepted += count
        if "padded" in cell["presentation"]: padded_attempts += count
        summary.append({"Mode": cell["mode"], "Case": cell["case"], "Policy": cell["policy"],
                        "Attempts": count, "Accepted": count if cell["accepted"] else 0,
                        "Rejected": 0 if cell["accepted"] else count, "Native_Paths": len(paths), "Result": "PASS"})
    with (directory / "summary.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(summary[0])); writer.writeheader(); writer.writerows(summary)
    checks = {"status": "PASS", "cells": len(cells), "attempts": len(cells) * count,
              "accepted": accepted, "issuer_policy_rejected": len(cells) * count - accepted,
              "native_validated": len(cells) * count, "business_requests": accepted,
              "padded_attempts": padded_attempts, "distinct_native_paths": len(observed_paths),
              "native_paths": [list(path) for path in sorted(observed_paths)],
              "android_system_roots": len(trusted), "same_csr": True,
              "unattributed_business_requests": unattributed,
              "direct_issuer_cross_signing_tested": False,
              "public_ancestor_cross_sign_chain_tested": True}
    (directory / "checks.json").write_text(json.dumps(checks, indent=2) + "\n")
    return checks


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    print(json.dumps(summarize(parser.parse_args().run_dir), indent=2))
