#!/usr/bin/env python3
"""Independently audit certificate-change evidence; never runs device tests."""
import argparse
from collections import Counter
import csv
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "certificate_change_runner_audit", ROOT / "run-certificate-change-benchmark.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def audit(directory):
    manifest = json.loads((directory / "manifest.json").read_text())
    if (manifest["state"] != "complete" or not manifest["deployment_restored"]
            or manifest["completed_cells"] != 15 or manifest["cells"] != runner.plan(manifest["run_id"])
            or any(manifest[k] for k in ("protected_state_reset", "clock_changed", "dns_changed"))
            or "eng.exp:" not in manifest["device_fingerprint"]):
        raise ValueError("A complete, restored, same-ASPin-image Internet run is required")
    started, finished = [datetime.fromisoformat(manifest[k]) for k in ("created_utc", "finished_utc")]
    if finished < started:
        raise ValueError("Invalid experiment interval")
    certificates = directory / "certificates"
    if runner.fixtures.inspect_fixtures(certificates, require_private_keys=False,
                                      at_time=started) != manifest["certificates"]:
        raise ValueError("Certificate fixtures or invariants differ from the run")
    hashes = runner.audit_policies(directory / "policies", certificates)
    if hashes != manifest["policy_sha256"]:
        raise ValueError("Policy bytes changed after the experiment")
    for name in hashes:
        payload = runner.signing.decode_payload(directory / "policies" / name)
        if not payload["iat"] <= started.timestamp() or payload["exp"] <= finished.timestamp():
            raise ValueError("The same token must be fresh throughout the recorded experiment")
    if runner.digest(directory / "scp-res/xml/network_security_config.xml") != manifest["scp_resource_sha256"]:
        raise ValueError("Static NSC pin configuration changed")
    counts, summary = Counter(), []
    for cell in manifest["cells"]:
        path = directory / (cell["scenario"] + ".csv")
        with path.open(newline="") as source:
            rows = list(csv.DictReader(source))
        expected = runner.comparison.validate(rows, cell, manifest["iterations"])
        evidence = json.loads(path.with_suffix(".audit.json").read_text())
        valid, business = runner.comparison.audit_requests(evidence["events"], cell,
            manifest["iterations"], manifest["warmups"], expected)
        metadata = [e for e in evidence["events"] if e.get("path", "").startswith("/.well-known/")]
        wanted = (1 if cell["scheme"] == "DCP" else
                  2 if cell["scheme"].startswith("ASPin") and cell["phase"] == "real" else 0)
        if (not valid or business["business_requests"] != evidence["business_requests"]
                or len(metadata) != wanted or evidence["metadata_requests"] != wanted
                or any(e.get("status") != 200 for e in metadata)
                or evidence["policy_sha256"] != hashes
                or evidence["presented_leaf_sha256"] != manifest["certificates"][cell["phase"]]["leaf_sha256"]
                or any(e.get("phase") != cell["phase"] for e in evidence["events"])):
            raise ValueError("Endpoint, request, or unchanged-policy audit mismatch")
        counts.update(row["Outcome"] for row in rows)
        summary.append({"scheme": cell["scheme"], "phase": cell["phase"],
            "attempts": len(rows), "accepted": sum(row["Outcome"] == "accepted" for row in rows),
            "policy_rejected": sum(row["Outcome"] == "policy_rejected" for row in rows),
            "expected": expected, "result": "PASS"})
    return {"result": "PASS", "cells": len(summary), "attempts": sum(counts.values()),
        "accepted": counts["accepted"], "policy_rejected": counts["policy_rejected"],
        "unchanged_direct_issuer": True, "unchanged_subject_san": True,
        "unchanged_tokens": True, "rows": summary}


def check_paper(results, text):
    """Match numeric table cells to audited observations, not prose spelling."""
    table = re.search(r"\\label\{table:evaluation-certificate-change\}(.*?)\\end\{table\}",
                      text, flags=re.DOTALL)
    if table is None:
        raise ValueError("Missing certificate-change evaluation table")
    by_cell = {(row["scheme"], row["phase"]): row for row in results["rows"]}
    schemes = ("TLS", "SCP", "DCP", "ASPin", "ASPin-compatible")
    for title, phase in (("Baseline", "real"), ("Renewal", "renewal"), ("TLS rekey", "rekey")):
        matches = re.findall(r"^\s*" + re.escape(title) + r"\s*&([^\n]+)",
                             table.group(1), flags=re.MULTILINE)
        if len(matches) != 1:
            raise ValueError("Missing or duplicate certificate-change table row: " + title)
        values = re.findall(r"(\d+)\s*/\s*(\d+)", matches[0])
        expected = [(str(by_cell[(s, phase)]["accepted"]), str(by_cell[(s, phase)]["attempts"]))
                    for s in schemes]
        if values != expected:
            raise ValueError("Certificate-change paper data differ from observations: " + title)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--check-paper", action="store_true",
                        help="Check the appendix accepted/attempts table against audited rows")
    args = parser.parse_args()
    directory = args.directory.resolve()
    results = audit(directory)
    if args.check_paper:
        check_paper(results, (ROOT / "tex/paper_appendix.tex").read_text())
    (directory / "checks.json").write_text(json.dumps(results, indent=2) + "\n")
    with (directory / "summary.csv").open("w", newline="") as target:
        writer = csv.DictWriter(target, results["rows"][0].keys())
        writer.writeheader(); writer.writerows(results["rows"])
    evidence = {}
    for path in directory.rglob("*"):
        if (path.is_file() and path.name != "evidence-sha256.json"
                and not path.name.endswith(("-key.pem", ".pk8", ".keystore"))
                and "apks" not in path.relative_to(directory).parts):
            evidence[str(path.relative_to(directory))] = hashlib.sha256(path.read_bytes()).hexdigest()
    (directory / "evidence-sha256.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in results.items() if k != "rows"}, indent=2))


if __name__ == "__main__":
    main()
