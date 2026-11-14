#!/usr/bin/env python3
"""Independently audit a completed 98-case remote functional suite."""
import argparse
import base64
import csv
import json
from pathlib import Path
import re


def one_csv(path):
    with path.open() as stream: rows = list(csv.DictReader(stream))
    if len(rows) != 1: raise ValueError(f"Expected one observation: {path.name}")
    return rows[0]


def payload(path):
    value = json.loads(path.read_text())["payload"]
    return json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    directory = args.directory
    manifest = json.loads((directory / "manifest.json").read_text())
    if manifest["state"] != "complete": raise ValueError("Refusing an incomplete functional run")
    cases = manifest["cases"]
    if len(cases) != 98 or len({case["scenario"] for case in cases}) != 98:
        raise ValueError("Missing, extra, or duplicate cases")
    counts, raw = {}, {}
    audited_requests = 0
    for case in cases:
        label = case["scenario"]
        if case["result"] != "PASS": raise ValueError(label)
        row = one_csv(directory / (label + ".csv"))
        if row["Result"] != "PASS": raise ValueError(label)
        mode, group = re.search(r"-(primary|compat)-(cross|parallel|tk-bound|tc-bound|migration|claim-key|app-root|ks-root)-", label).groups()
        counts[mode, group] = counts.get((mode, group), 0) + 1
        raw[label] = row
        if "Scenario" in row:
            if row["Scenario"] != label or row["Outcome"] != row["Expected_Outcome"]:
                raise ValueError("Unexpected functional decision")
            audit = json.loads((directory / (label + ".audit.json")).read_text())
            wanted = int(row["Outcome"] == "accepted")
            if audit != {"business_requests": wanted, "expected": wanted}:
                raise ValueError("Request audit mismatch")
            audited_requests += 1
            if row["Outcome"] == "lookup_refused" and (row["TLS_Attempted"] != "false" or row["App_Request_Sent"] != "false"):
                raise ValueError("Lookup refusal continued a protected connection")
            if label.endswith("metadata-timeout") and float(row["Outcome_ms"]) < 9000:
                raise ValueError("Timeout case did not wait for the configured read timeout")
        elif (row["Label"] != label or row["ExpectedSuccess"] != "false" or row["ObservedSuccess"] != "false"
              or row["ForceRefresh"] != "true" or row["ReasonMatch"] != "true"
              or "anti-rollback" not in row["Error"].lower()):
            raise ValueError("Unexpected claim-only replay decision")
    for mode in ("primary", "compat"):
        if sum(value for (m, _), value in counts.items() if m == mode) != 49:
            raise ValueError("Expected 49 observations per mode")
        for bound in ("tk-bound", "tc-bound"):
            tk = payload(directory / f"{mode}-{bound}-tk.jws")
            tc = payload(directory / f"{mode}-{bound}-tc.jws")
            expiry = min(tk["exp"], tc["exp"]) * 1000
            if (tk["exp"] < tc["exp"]) != (bound == "tk-bound"):
                raise ValueError("Wrong token imposes the expiration bound")
            for label, row in raw.items():
                if f"-{mode}-{bound}-" not in label: continue
                if label.endswith("prime") and int(row["Expires_ms"]) != expiry:
                    raise ValueError("OS did not return the joint expiration bound")
                if label.endswith(("expired-self", "expired-cross")) and int(row["Lookup_Start_ms"]) < expiry:
                    raise ValueError("Expiration not reached on the device")
    for stage in manifest["migration_staging"]:
        if stage["elapsed_seconds"] < stage["lmax_seconds"]:
            raise ValueError("Staging interval was shortened")
    old_ks = payload(directory / "compat-ks-root-old-tk.jws")
    new_ks = payload(directory / "compat-ks-root-new-tk.jws")
    if new_ks["iat"] >= old_ks["iat"]: raise ValueError("Independent lower-iat manifest namespace was not tested")
    checks = {"cases": len(cases), "policy_request_audits": audited_requests,
              "claim_only_rollback_probes": len(cases) - audited_requests,
              "expiration_bounds_rechecked": 4, "staging_intervals_rechecked": len(manifest["migration_staging"]),
              "result": "PASS"}
    (directory / "checks.json").write_text(json.dumps(checks, indent=2) + "\n")
    with (directory / "functional-groups.csv").open("w", newline="") as stream:
        writer = csv.writer(stream); writer.writerow(("Mode", "Group", "Cases", "Result"))
        for (mode, group), count in sorted(counts.items()): writer.writerow((mode, group, count, "PASS"))
    print(json.dumps(checks))


if __name__ == "__main__":
    main()
