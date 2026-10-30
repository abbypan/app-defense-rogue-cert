#!/usr/bin/env python3
"""Audit one fresh Internet cohort; never falls back to earlier measurements."""
import argparse
import csv
from datetime import datetime
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import statistics
import subprocess
import sys

from jwcrypto import jwk, jws
from cryptography import x509
from cryptography.hazmat.primitives import hashes

ROOT = Path(__file__).resolve().parent
ALGORITHMS = ("es256", "es384", "rsa3072", "rsa4096")


def read_csv(path):
    with path.open(newline="") as source: return list(csv.DictReader(source))


def load(filename):
    spec = importlib.util.spec_from_file_location(filename.replace("-", "_"), ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fresh_complete(path, started):
    manifest = json.loads(path.read_text())
    if manifest["state"] != "complete": raise ValueError("Incomplete: " + str(path))
    if datetime.fromisoformat(manifest["created_utc"]) < started:
        raise ValueError("Historical evidence cannot enter this cohort")
    return manifest


def expected_cached_dimensions(cross_algorithms):
    if (not cross_algorithms or len(set(cross_algorithms)) != len(cross_algorithms)
            or not set(cross_algorithms).issubset(ALGORITHMS)):
        raise ValueError("Invalid cross-app profile inventory")
    return {(mode, alg, kind, threads)
            for mode in ("primary", "compat") for kind in ("self", "cross")
            for alg in (ALGORITHMS if kind == "self" else cross_algorithms)
            for threads in (1, 8)}


def validate_cached_context(row, case, operations):
    expected_api = "self" if case["caller"] == "com.cert.aspin" else "cross"
    if (row.get("API") != expected_api or row.get("Hostname") != case["algorithm"] + ".idouzi.top"
            or row.get("TargetAppId") != "com.cert.aspin"):
        raise ValueError("Cached API row has the wrong query or target context")
    if (int(row["Operations"]) != operations or int(row["Successes"]) != operations
            or int(row["Failures"]) != 0 or int(row["Threads"]) not in (1, 8)):
        raise ValueError("Incomplete cached API batch")
    for field in ("Mean_ms", "P50_ms", "P95_ms", "P99_ms", "Throughput_ops_s"):
        if not math.isfinite(float(row[field])) or float(row[field]) <= 0:
            raise ValueError("Invalid cached API metric")
    if not float(row["P50_ms"]) <= float(row["P95_ms"]) <= float(row["P99_ms"]):
        raise ValueError("Unordered cached API percentiles")


def audit_cached_matrix(directory, cohort_started, fingerprint):
    """A later complete session supersedes API timings, never fills cells by imputation."""
    manifest_path = directory / "manifest.json"
    manifest = fresh_complete(manifest_path, cohort_started)
    if (manifest.get("schema_version") != 2 or manifest.get("suite") != "cache-matrix"
            or manifest["device_fingerprint"] != fingerprint
            or manifest.get("clock_rollback_seconds") != 0
            or set(manifest.get("cross_algorithms", [])) != set(ALGORITHMS)):
        raise ValueError("Expected a complete, same-image cached API matrix")
    started = datetime.fromisoformat(manifest["created_utc"])
    finished = datetime.fromisoformat(manifest["finished_utc"])
    if finished < started:
        raise ValueError("Invalid supplemental session interval")
    required_apks = {"ASPin-" + alg + suffix + ".apk" for alg in ALGORITHMS
                     for suffix in ("", "-compatible")} | {
                         "ASPin-caller-es256.apk", "ASPin-caller-es384.apk"}
    if set(manifest["apk_sha256"]) != required_apks:
        raise ValueError("Incomplete target/caller APK inventory")
    for filename, expected in manifest["apk_sha256"].items():
        if hashlib.sha256((directory / "apks" / filename).read_bytes()).hexdigest() != expected:
            raise ValueError("Supplemental API APK changed")
    apksigner = load("gen-signed-apks.py").resolve_tool("apksigner")
    signer_hashes = {alg: x509.load_pem_x509_certificate(
        (ROOT / "signing" / alg / "my-app-cert.pem").read_bytes()).fingerprint(hashes.SHA256()).hex()
        for alg in ALGORITHMS}
    if len(set(signer_hashes.values())) != len(ALGORITHMS):
        raise ValueError("Target profiles do not have distinct signing certificates")
    for filename in required_apks:
        certificate_output = subprocess.run(
            [str(apksigner), "verify", "--print-certs", str(directory / "apks" / filename)],
            check=True, text=True, capture_output=True).stdout
        actual = re.findall(r"Signer #\d+ certificate SHA-256 digest: ([a-fA-F0-9]+)", certificate_output)
        algorithm = re.fullmatch(r"ASPin-(?:caller-)?(es256|es384|rsa3072|rsa4096)(?:-compatible)?\.apk", filename)[1]
        if actual != [signer_hashes[algorithm]]:
            raise ValueError("Wrong target/caller APK signing certificate")
    paths = [manifest_path]
    for alg in ALGORITHMS:
        artifact_dir = directory / "policy-artifacts" / alg
        for mode, stem in (("primary", "my-app"), ("compat", "my-dcp")):
            tk_path = artifact_dir / ("ClaimSigningKey." + mode + ".jws")
            tc_path = artifact_dir / "ServerCertClaim.jws"
            token = jws.JWS()
            token.deserialize(tk_path.read_text())
            token.verify(jwk.JWK.from_pem((ROOT / "signing" / alg / (stem + "-pubkey.pem")).read_bytes()))
            delegation = json.loads(token.payload)
            token.deserialize(tc_path.read_text())
            token.verify(jwk.JWK(**delegation["cnf"]["jwk"]))
            claim = json.loads(token.payload)
            for payload in (delegation, claim):
                if payload["iat"] < int(started.timestamp()) or payload["exp"] <= finished.timestamp():
                    raise ValueError("Supplemental API policy is not fresh for its measurement session")
            paths.extend([tk_path, tc_path])
    cases = manifest["cases"]
    if len(cases) != 64 or len({case["file"] for case in cases}) != 64:
        raise ValueError("Incomplete supplemental API checks")
    rows = []
    for case in cases:
        if case["algorithm"] not in ALGORITHMS or case["mode"] not in ("primary", "compat"):
            raise ValueError("Unknown supplemental API profile")
        path = directory / case["file"]
        observed = read_csv(path)
        if len(observed) != 1 or observed[0]["Result"] != "PASS" or case["result"] != "PASS":
            raise ValueError("Failed supplemental API check")
        row = observed[0]
        audit = json.loads(path.with_suffix(".audit.json").read_text())
        if audit["business_requests"] != 0 or audit["unattributed_business_requests"]:
            raise ValueError("Supplemental API check sent a business request")
        if case["caller"] == "com.cert.aspin.caller":
            expected_signer = "es256" if case["algorithm"] == "es384" else "es384"
            if case.get("caller_signing_variant") != expected_signer:
                raise ValueError("Cross-app caller must differ from the target signer")
        elif case["caller"] != "com.cert.aspin":
            raise ValueError("Unknown supplemental caller")
        if case["kind"] == "concurrency":
            validate_cached_context(row, case, manifest["operations"])
            if audit["metadata_requests"] != 0:
                raise ValueError("Supplemental cache timing included metadata retrieval")
            rows.append({"Mode": case["mode"], "Algorithm": case["algorithm"], **row})
        elif case["kind"] == "claimprobe":
            if row["ObservedSuccess"] != "true" or row["ReasonMatch"] != "true":
                raise ValueError("Unexpected supplemental cache/prime decision")
            if row["ForceRefresh"] == "true":
                paths_seen = {event["path"] for event in audit["events"]
                              if event.get("status") == 200 and event.get("host") == case["algorithm"] + ".idouzi.top"}
                if not {"/.well-known/ClaimSigningKey.jws", "/.well-known/ServerCertClaim.jws"}.issubset(paths_seen):
                    raise ValueError("Missing Internet token-retrieval evidence")
            elif (audit["metadata_requests"] != 0 or float(row["Tk_ms"]) != 0 or float(row["Tc_ms"]) != 0):
                raise ValueError("Supplemental cache probe was not a pure hit")
        else:
            raise ValueError("Unexpected supplemental API operation")
        paths.extend([path, path.with_suffix(".audit.json")])
    dimensions = [(r["Mode"], r["Algorithm"], r["API"], int(r["Threads"])) for r in rows]
    if len(dimensions) != 32 or set(dimensions) != expected_cached_dimensions(ALGORITHMS):
        raise ValueError("Incomplete supplemental self/cross-app dimensions")
    return manifest, rows, paths


def cached_api_table_lines(api_rows, algorithms):
    """Keep missing query/profile combinations explicit, never impute measurements."""
    lines = []
    for alg, label in algorithms:
        for api_kind, query_label in (("self", "Self-query"), ("cross", "Cross-app query")):
            values = []
            for mode in ("primary", "compat"):
                matches = [r for r in api_rows if r["Mode"] == mode and r["Algorithm"] == alg
                           and r["API"] == api_kind and str(r["Threads"]) == "8"]
                if len(matches) > 1:
                    raise ValueError("Duplicate cached API batch: " + str((mode, alg, api_kind)))
                if matches:
                    row = matches[0]
                    values.extend((f"{float(row['P99_ms']):.2f}",
                                   f"{float(row['Throughput_ops_s']):,.0f}"))
                else:
                    values.extend(("--", "--"))
            lines.append(" & ".join([label, query_label, *values]) + r"\\")
    return lines


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--check-paper", action="store_true",
                        help="Also match every reported numerical table to this cohort")
    args = parser.parse_args()
    directory = args.directory.resolve()
    cohort = json.loads((directory / "cohort.json").read_text())
    if cohort["state"] != "complete" or cohort["historical_measurements_reused"] is not False:
        raise ValueError("A fresh, complete Internet cohort is required")
    started = datetime.fromisoformat(cohort["created_utc"])
    matrix = fresh_complete(directory / "comparison/matrix.json", started)
    functional = fresh_complete(directory / "functional/manifest.json", started)
    cross = fresh_complete(directory / "public-cross/manifest.json", started)
    api = fresh_complete(directory / "api-robustness/manifest.json", started)
    if (matrix["device"]["ro.build.fingerprint"] != cross["device_fingerprint"]
            or cross["device_fingerprint"] != api["device_fingerprint"]
            or matrix["device"]["ro.build.user"] != "exp"):
        raise ValueError("The suites did not use the same exp ASPin image")
    for filename, expected_hash in matrix["apk_sha256"].items():
        if hashlib.sha256((directory / "apks" / filename).read_bytes()).hexdigest() != expected_hash:
            raise ValueError("The archived matrix APK changed")
    comparison = load("run-remote-comparison.py")
    if len(matrix["cells"]) != 64: raise ValueError("Incomplete connection matrix")
    expected_plan = {(c["scheme"], c["algorithm"], c["phase"], c["cache"]) for c in comparison.plan()}
    if {(c["scheme"], c["algorithm"], c["phase"], c["cache"]) for c in matrix["cells"]} != expected_plan:
        raise ValueError("Wrong connection dimensions")
    attempts, accepted, raw_paths, cell_stats = 0, 0, [], {}
    for cell in matrix["cells"]:
        path = directory / "comparison" / (cell["scenario"] + ".csv")
        rows = read_csv(path)
        outcome = comparison.validate(rows, cell, matrix["iterations"])
        audit = json.loads(path.with_suffix(".audit.json").read_text())
        expected_requests = len(rows) if outcome == "accepted" else 0
        if audit["business_requests"] != expected_requests or audit["expected_business_requests"] != expected_requests:
            raise ValueError("Missing per-cell request audit")
        wanted_tags = [cell["scenario"] + "-" + str(i) for i in range(1, len(rows) + 1)] if expected_requests else []
        if sorted(audit["measured_tags"]) != sorted(wanted_tags): raise ValueError("Wrong request identities")
        if cell["scheme"] == "DCP":
            wanted = 1 if cell["cache"] == "hot" else matrix["warmups"] + len(rows)
            if audit["metadata_requests"] != wanted: raise ValueError("Wrong DCP cache evidence")
        attempts += len(rows); accepted += expected_requests
        raw_paths.extend([path, path.with_suffix(".audit.json")])
        timings = sorted(float(row["Outcome_ms"]) for row in rows)
        cell_stats[cell["scheme"], cell["algorithm"], cell["phase"], cell["cache"]] = {
            "mean": statistics.mean(timings), "p95": timings[math.ceil(len(timings) * .95) - 1]}
    subprocess.run([sys.executable, ROOT / "summarize-remote-functional.py", directory / "functional"], check=True)
    cross_checks = load("summarize-public-cross-results.py").summarize(directory / "public-cross")
    api_rows = []
    api_cases = api["cases"]
    if len({case["file"] for case in api_cases}) != len(api_cases): raise ValueError("Duplicate API cases")
    for mode in ("primary", "compat"):
        for name in ("earlier-accepted", "higher-accepted", "reboot-old-tc", "reboot-old-tk",
                     "reboot-current", "clock-rollback-600s", "clock-restored", "parallel-host-refresh"):
            if sum(case["file"].endswith(f"-{mode}-{name}.csv") for case in api_cases) != 1:
                raise ValueError("Missing or duplicated robustness check: " + mode + " " + name)
    for case in api_cases:
        path = directory / "api-robustness" / case["file"]
        rows = read_csv(path)
        if len(rows) != 1 or rows[0]["Result"] != "PASS": raise ValueError("Failed API observation")
        row = rows[0]
        audit = json.loads(path.with_suffix(".audit.json").read_text())
        if audit["business_requests"] != 0: raise ValueError("API-only probe issued a business request")
        if case["kind"] == "concurrency":
            count = int(row["Operations"])
            if int(row["Successes"]) != count or int(row["Failures"]) != 0 or audit["metadata_requests"] != 0:
                raise ValueError("Not a complete metadata-free cached API run")
            for field in ("Mean_ms", "P50_ms", "P95_ms", "P99_ms", "Throughput_ops_s"):
                if not math.isfinite(float(row[field])) or float(row[field]) <= 0: raise ValueError("Invalid API metric")
            api_rows.append({"Mode": case["mode"], "Algorithm": case["algorithm"],
                             "API": "self" if case["caller"] == "com.cert.aspin" else "cross", **row})
        elif case["kind"] == "claimprobe":
            rejected = any(name in case["file"] for name in ("-reboot-old-tc", "-reboot-old-tk", "-clock-rollback"))
            if row["ObservedSuccess"] != str(not rejected).lower() or row["ReasonMatch"] != "true":
                raise ValueError("Unexpected robustness decision")
            reason = "fresh" if "-clock-rollback" in case["file"] else "anti-rollback"
            if rejected and reason not in row["Error"].lower(): raise ValueError("Wrong refusal reason")
        raw_paths.extend([path, path.with_suffix(".audit.json")])
    expected_api = expected_cached_dimensions(api.get("cross_algorithms", ["es256"]))
    if {(r["Mode"], r["Algorithm"], r["API"], int(r["Threads"])) for r in api_rows} != expected_api:
        raise ValueError("Incomplete API/concurrency dimensions")
    original_api_runs = len(api_rows)
    supplement = None
    supplement_dir = directory / "api-cache-matrix"
    if supplement_dir.exists():
        supplement, api_rows, supplemental_paths = audit_cached_matrix(
            supplement_dir, started, api["device_fingerprint"])
        raw_paths.extend(supplemental_paths)
    with (directory / "api-summary.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, list(api_rows[0])); writer.writeheader(); writer.writerows(api_rows)
    # Capture sizes from the actual fresh matrix generation, not an older table.
    sizes = {}
    for alg in comparison.ALGORITHMS:
        source = directory / "matrix-artifacts" / alg
        delegations = []
        for mode, stem in (("primary", "my-app"), ("compat", "my-dcp")):
            verifier = jws.JWS()
            verifier.deserialize((source / ("ClaimSigningKey." + mode + ".jws")).read_text())
            verifier.verify(jwk.JWK.from_pem((ROOT / "signing" / alg / (stem + "-pubkey.pem")).read_bytes()))
            delegation = json.loads(verifier.payload)
            if delegation["iat"] < int(started.timestamp()) or delegation["exp"] <= delegation["iat"]:
                raise ValueError("Matrix delegation predates this cohort or has invalid lifetime")
            delegations.append(delegation)
            verifier = jws.JWS()
            verifier.deserialize((source / "ServerCertClaim.jws").read_text())
            verifier.verify(jwk.JWK(**delegation["cnf"]["jwk"]))
            claim = json.loads(verifier.payload)
            if claim["iat"] < int(started.timestamp()) or claim["exp"] <= claim["iat"]:
                raise ValueError("Matrix claim predates this cohort or has invalid lifetime")
        if (delegations[0]["cnf"] != delegations[1]["cnf"]
                or delegations[0]["exp"] - delegations[0]["iat"] != delegations[1]["exp"] - delegations[1]["iat"]):
            raise ValueError("Root modes delegate different keys or lifetimes")
        sizes[alg] = {filename: (source / filename).stat().st_size for filename in
                      ("ClaimSigningKey.primary.jws", "ClaimSigningKey.compat.jws", "ServerCertClaim.jws", "DCPServerCertPin.jws")}
        raw_paths.extend(source.glob("*.jws"))
    for folder in ("functional", "public-cross"):
        raw_paths.extend(path for pattern in ("*.csv", "*.audit.json", "*.jws", "manifest.json", "checks.json")
                         for path in (directory / folder).glob(pattern))
    provenance = {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in sorted(set(raw_paths))}
    apk_hashes = {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for folder in ("apks", "public-cross/apks", "api-cache-matrix/apks")
                  for path in (directory / folder).glob("*.apk")}
    (directory / "evidence-sha256.json").write_text(json.dumps(provenance, indent=2) + "\n")
    findings = {"result": "PASS", "historical_measurements_reused": False,
                "connection_cells": len(matrix["cells"]), "connection_attempts": attempts,
                "connection_accepted": accepted, "connection_policy_rejected": attempts - accepted,
                "functional_cases": len(functional["cases"]), "public_cross": cross_checks,
                "api_cases": len(api_cases), "cached_api_runs": len(api_rows),
                "cached_api_operations": sum(int(r["Operations"]) for r in api_rows),
                "migration_staging": functional["migration_staging"], "artifact_sizes": sizes,
                "apk_sha256": apk_hashes,
                "hashed_evidence_files": len(provenance)}
    if supplement is not None:
        findings["cached_api_session"] = {
            "source": "api-cache-matrix", "cases": len(supplement["cases"]),
            "original_cached_runs_retained": original_api_runs,
            "created_utc": supplement["created_utc"], "finished_utc": supplement["finished_utc"],
            "same_device_image": True, "complete_self_cross_matrix": True,
            "all_callers_differ_from_target_signer": True, "verified_apk_signatures": 10}
    startup_path = directory / "api-robustness-failed-startup/manifest.json"
    if startup_path.exists():
        startup = json.loads(startup_path.read_text())
        if startup["state"] != "failed" or startup["cases"]:
            raise ValueError("Unexpected observations in the excluded startup attempt")
        findings["excluded_api_startup"] = {"state": "failed", "observations": 0,
                                           "reason": "empty adb/am launch argument; corrected before measurement"}
    if args.check_paper:
        main_text = (ROOT / "tex/paper_content.tex").read_text()
        appendix = (ROOT / "tex/paper_appendix.tex").read_text()
        def table(text, label):
            match = re.search(re.escape("\\label{" + label + "}") + r"(.*?)\\end\{table\}", text, re.S)
            if not match: raise ValueError("Missing paper table: " + label)
            return {line.strip() for line in match[1].splitlines()}
        connection_lines = table(main_text, "table:connectiontime")
        cold_lines = table(main_text, "table:osveriftime")
        size_lines = table(appendix, "table:artifactsize")
        api_lines = table(appendix, "table:internet-api")
        algorithms = (("rsa3072", "PS256"), ("rsa4096", "PS384"), ("es256", "ES256"), ("es384", "ES384"))
        for phase in ("real", "rogue"):
            for scheme, label in (("TLS", "TLS"), ("SCP", "SCP"), ("DCP", "DCP"),
                    ("ASPin", "ASPin ($K_{apub}$)"), ("ASPin-compatible", "ASPin ($K_{spub}$)")):
                cache = {"TLS": "none", "SCP": "static"}.get(scheme, "hot")
                values = [f"{cell_stats[scheme, alg, phase, cache]['mean']:.2f}" for alg, _ in algorithms]
                n = matrix["iterations"] if phase == "real" or scheme == "TLS" else 0
                expected_line = " & ".join([label, *values, str(n)]) + r"\\"
                if expected_line not in connection_lines: raise ValueError("Stale connection table: " + expected_line)
        for alg, label in algorithms:
            values = [f"{cell_stats[scheme, alg, 'real', 'cold-forced-refresh'][field]:.2f}"
                      for scheme in ("DCP", "ASPin", "ASPin-compatible") for field in ("mean", "p95")]
            if " & ".join([label, *values]) + r"\\" not in cold_lines: raise ValueError("Stale cold table: " + label)
        for label, files in (("DCP signed pin", ("DCPServerCertPin.jws",)),
                (r"ASPin $T_k$", ("ClaimSigningKey.primary.jws",)), (r"ASPin $T_c$", ("ServerCertClaim.jws",)),
                (r"ASPin $T_k+T_c$", ("ClaimSigningKey.primary.jws", "ServerCertClaim.jws"))):
            values = [f"{sum(sizes[alg][name] for name in files):,}" for alg, _ in algorithms]
            if " & ".join([label, *values]) + r"\\" not in size_lines: raise ValueError("Stale size table")
        for expected_line in cached_api_table_lines(api_rows, algorithms):
            if expected_line not in api_lines:
                raise ValueError("Stale API table: " + expected_line)
        findings["paper_tables_match_fresh_evidence"] = True
    (directory / "checks.json").write_text(json.dumps(findings, indent=2) + "\n")
    print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
