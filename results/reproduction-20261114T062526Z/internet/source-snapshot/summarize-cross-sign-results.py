#!/usr/bin/env python3
"""Independently verify saved cross-sign paths, signed policy and HTTP audits."""
import argparse
import csv
import hashlib
import importlib.util
import json
import math
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from jwcrypto import jwk, jws

ROOT = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RUNNER = load("cross_sign_runner", "run-cross-sign-benchmark.py")
VALIDATOR = load("cross_sign_evidence", "summarize-lifecycle-results.py")


def signed_payload(filename, key):
    token = jws.JWS()
    value = json.loads(filename.read_text())
    if not isinstance(value.get("signatures"), list) or not value["signatures"]:
        raise ValueError("General JWS signatures array required")
    token.deserialize(json.dumps(value))
    token.verify(key)
    return json.loads(token.payload)


def summarize(directory):
    manifest = json.loads((directory / "manifest.json").read_text())
    if manifest["state"] != "complete" or manifest.get("restored") is not True:
        raise ValueError("A complete, restored run is required")
    with (directory / "restored-policies/claimprobe.csv").open(newline="") as stream:
        restored = list(csv.DictReader(stream))
    if (len(restored) != 1 or any(restored[0].get(field) != expected for field, expected in
            (("Result", "PASS"), ("ObservedSuccess", "true"), ("ForceRefresh", "true")))):
        raise ValueError("Missing successful restored public-CA claim lookup")
    iterations = manifest["iterations"]
    if not isinstance(iterations, int) or iterations <= 0: raise ValueError("Invalid attempt count")
    fixture = directory / "artifacts/cross-sign"
    def cert(name): return x509.load_pem_x509_certificate((fixture / name).read_bytes())
    a, b, leaf = cert("direct-a.pem"), cert("direct-b.pem"), cert("leaf.pem")
    def spki(c): return c.public_key().public_bytes(serialization.Encoding.DER,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo)
    if a.subject != b.subject or spki(a) != spki(b) or a.issuer == b.issuer:
        raise ValueError("Expected one intermediate identity signed by two roots")
    a.verify_directly_issued_by(cert("root-a.pem"))
    b.verify_directly_issued_by(cert("root-b.pem"))
    leaf.verify_directly_issued_by(a); leaf.verify_directly_issued_by(b)
    wrong = cert("rogue-direct.pem")
    wrong.verify_directly_issued_by(cert("root-a.pem"))
    cert("rogue-leaf.pem").verify_directly_issued_by(wrong)
    if wrong.subject != a.subject or spki(wrong) == spki(a):
        raise ValueError("Same-name wrong-key negative control is missing")
    id_a, id_b = (VALIDATOR.certificate_id(fixture / name) for name in ("direct-a.pem", "direct-b.pem"))
    if id_a == id_b: raise ValueError("Distinct DER certificate identifiers required")
    expected_cells = {(mode, case[0]): case for mode in ("primary", "compatible") for case in RUNNER.cases()}
    cells = manifest["cells"]
    if len(cells) != 12 or {(cell["mode"], cell["case"]) for cell in cells} != set(expected_cells):
        raise ValueError("Missing or duplicate mode/case")
    if len({cell["scenario"] for cell in cells}) != 12: raise ValueError("Repeated audit label")
    policies = {}
    for mode in ("primary", "compatible"):
        root_key = jwk.JWK.from_pem((fixture / (mode + "-root.pem")).read_bytes())
        delegation = signed_payload(directory / (mode + "-key.jws"), root_key)
        claim_key = jwk.JWK(**delegation["cnf"]["jwk"])
        for kind, expected in (("incomplete", {id_a}), ("complete", {id_a, id_b})):
            claim = signed_payload(directory / (mode + "-" + kind + ".jws"), claim_key)
            if set(claim["issuer"]) != expected or len(claim["issuer"]) != len(expected):
                raise ValueError("Unexpected signed IssuerSet")
            if claim["subject"] != leaf.subject.rfc4514_string(): raise ValueError("Wrong signed Subject")
            names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            if claim["san"] != names.get_values_for_type(x509.DNSName): raise ValueError("Wrong signed SAN")
            if not delegation["iat"] <= claim["iat"] < min(claim["exp"], delegation["exp"]):
                raise ValueError("Invalid signed times")
            policies[mode, kind] = claim
        if policies[mode, "incomplete"]["iat"] >= policies[mode, "complete"]["iat"]:
            raise ValueError("Complete publication must advance iat")
    summary, accepted_count = [], 0
    for cell in cells:
        mode, name = cell["mode"], cell["case"]
        expected = expected_cells[mode, name]
        if cell["policy"] != expected[-1] or cell["accepted"] != expected[4] or cell["result"] != "PASS":
            raise ValueError("Manifest case disagrees with protocol")
        filename = mode + "-" + name + ".csv"
        if cell["file"] != filename: raise ValueError("Unexpected raw evidence path")
        with (directory / filename).open(newline="") as stream: rows = list(csv.DictReader(stream))
        if len(rows) != iterations: raise ValueError("Missing measured attempts")
        VALIDATOR.validate_cross_sign(rows, "cross-sign-" + name + ".csv", directory)
        for row in rows:
            if row.get("Mode") != mode or row["Scenario"] != cell["scenario"]:
                raise ValueError("Wrong root mode or observation label")
            if set(row["Claim_Issuers"].split(";")) != set(policies[mode, cell["policy"]]["issuer"]):
                raise ValueError("Returned OS policy differs from authenticated publication")
            for field in ("Tk_ms", "Tc_ms"):
                value = float(row[field])
                if not math.isfinite(value) or value <= 0: raise ValueError("Missing forced OS verification evidence")
        audit = json.loads((directory / filename).with_suffix(".audit.json").read_text())
        RUNNER.audit_requests(audit, cell["scenario"], iterations, cell["accepted"])
        if cell["accepted"]: accepted_count += iterations
        summary.append({"Mode": mode, "Case": name, "Attempts": iterations,
                        "Native_Valid": iterations, "Accepted": iterations if cell["accepted"] else 0,
                        "Policy_Rejected": 0 if cell["accepted"] else iterations, "Result": "PASS"})
    with (directory / "summary.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(summary[0]))
        writer.writeheader(); writer.writerows(summary)
    checks = {"cells": len(cells), "attempts": iterations * len(cells),
              "accepted": accepted_count, "issuer_policy_rejected": iterations * len(cells) - accepted_count,
              "native_validated": iterations * len(cells), "business_requests": accepted_count,
              "modes": ["primary", "compatible"], "restoration_claim_probe": "PASS",
              "apk_sha256": {mode: hashlib.sha256((directory / "apks" /
                  ("ASPin-es256" + suffix + ".apk")).read_bytes()).hexdigest()
                  for mode, suffix in (("primary", ""), ("compatible", "-compatible"))
                  if (directory / "apks" / ("ASPin-es256" + suffix + ".apk")).is_file()},
              "status": "PASS"}
    (directory / "checks.json").write_text(json.dumps(checks, indent=2) + "\n")
    return checks


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    print(json.dumps(summarize(parser.parse_args().run_dir), indent=2))
