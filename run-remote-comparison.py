#!/usr/bin/env python3
"""Four-scheme Pixel-8 -> hk:443 comparison, never a stock-Android experiment.

Uses only the existing isolated deployment and current test-domain SNI routing.
No global network shaping or local/ADB HTTP forwarding is used. DNS changes
only when explicitly requested through ASPIN_BENCHMARK_DNS.
"""
import argparse
import atexit
import csv
import fcntl
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
import re
from pathlib import Path
import shlex
import statistics
import subprocess
import time
import uuid
from benchmark_device_network import wait_for_internet

ROOT = Path(__file__).resolve().parent
PACKAGE = "com.cert.aspin"
MODES = {"TLS": ("primary", "", ("none",)), "SCP": ("scp", "-scp", ("static",)),
         "DCP": ("dcp", "-dcp", ("hot", "cold-forced-refresh")),
         "ASPin": ("primary", "", ("hot", "cold-forced-refresh")),
         "ASPin-compatible": ("compatible", "-compatible", ("hot", "cold-forced-refresh"))}
ALGORITHMS = ("es256", "es384", "rsa3072", "rsa4096")


def plan(prefix=""):
    return [{"scheme": scheme, "mode": mode, "suffix": suffix, "algorithm": algorithm,
             "phase": phase, "cache": cache,
             "scenario": (prefix + "-" if prefix else "") + f"{scheme.lower()}-{algorithm}-{phase}-{cache}"}
            for scheme, (mode, suffix, caches) in MODES.items() for algorithm in ALGORITHMS
            for phase in ("real", "rogue") for cache in caches]


def run(command, check=True):
    return subprocess.run(list(map(str, command)), check=check, capture_output=True, text=True).stdout


def expected_outcome(scheme, phase):
    if scheme not in MODES or phase not in ("real", "rogue", "renewal", "rekey"):
        raise ValueError("Unknown scheme or certificate phase")
    rejected = ((phase == "rogue" and scheme != "TLS")
                or (phase == "rekey" and scheme in ("SCP", "DCP")))
    return "policy_rejected" if rejected else "accepted"


def validate(rows, cell, iterations, record_transport_failures=False):
    if len(rows) != iterations:
        raise ValueError("Missing comparison samples")
    expected = expected_outcome(cell["scheme"], cell["phase"])
    for sample, row in enumerate(rows, 1):
        for field, key in (("Algorithm", "algorithm"), ("Phase", "phase"), ("Cache", "cache")):
            if row.get(field) != cell[key]: raise ValueError("Incorrect comparison " + field)
        transport_failure = (record_transport_failures and row["Outcome"] == "network_error"
                             and row["Result"] == "FAIL" and row["App_Request_Sent"] == "false"
                             and bool(row.get("Error_Class")))
        if (row["Scenario"] != cell["scenario"] or row["Scheme"] != cell["scheme"]
                or row["Mode"] != cell["mode"] or row["Sample"] != str(sample)
                or row["Expected_Outcome"] != expected
                or (not transport_failure and (row["Outcome"] != expected or row["Result"] != "PASS"
                    or row["App_Request_Sent"] != str(expected == "accepted").lower()))):
            raise ValueError(f"Invalid observation: {row}")
        for field in ("Policy_ms", "Connection_ms", "Outcome_ms", "AppRead_ms", "Tk_ms", "Tc_ms"):
            if not math.isfinite(float(row[field])) or float(row[field]) < 0:
                raise ValueError("Invalid timing: " + field)
        if not transport_failure and cell["scheme"] in ("ASPin", "ASPin-compatible"):
            tk, tc = float(row["Tk_ms"]), float(row["Tc_ms"])
            if cell["cache"] == "hot" and (tk != 0 or tc != 0):
                raise ValueError("ASPin hot observation unexpectedly fetched policy")
            if cell["cache"] == "cold-forced-refresh" and (tk <= 0 or tc <= 0):
                raise ValueError("ASPin cold observation did not fetch both tokens")
    return expected


def audit_requests(observations, cell, iterations, warmups, expected, accepted_samples=None,
                   transport_failures=0):
    """Require every measured request once; unique tags isolate repeated runs."""
    tags = {cell["scenario"] + "-" + str(i) for i in range(1, iterations + 1)}
    business = [item for item in observations if item.get("path") == "/"
                and item.get("observation") in tags]
    expected_tags = (tags if accepted_samples is None else
                     {cell["scenario"] + "-" + str(i) for i in accepted_samples}) if expected == "accepted" else set()
    seen = [item.get("observation") for item in business]
    audit = {"business_requests": len(business), "expected_business_requests": len(expected_tags),
             "measured_tags": sorted(seen)}
    valid = (set(seen) == expected_tags and len(seen) == len(expected_tags)
             and all(item.get("status") == 200 for item in business))
    if cell["scheme"] == "DCP":
        requests = [item for item in observations if item.get("path") == "/.well-known/DCPServerCertPin.jws"]
        wanted = 1 if cell["cache"] == "hot" else warmups + iterations
        minimum = wanted - transport_failures if cell["cache"] != "hot" else wanted
        audit.update(metadata_requests=len(requests), expected_metadata_requests=wanted,
                     minimum_metadata_requests=minimum, transport_failures=transport_failures)
        valid = valid and minimum <= len(requests) <= wanted and all(item.get("status") == 200 for item in requests)
    return valid, audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", default="3A201FDJH000GP")
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--apk-dir", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--record-transport-failures", action="store_true",
                        help="Keep network errors as failures, outside expected-outcome latency distributions")
    parser.add_argument("--schemes", nargs="+", choices=tuple(MODES), default=list(MODES),
                        help="Explicit fixed group order or a diagnostic subset")
    parser.add_argument("--resume", action="store_true", help="Continue a failed run after its last fully audited cell")
    args = parser.parse_args()
    if args.iterations <= 0 or args.warmups < 0 or args.timeout <= 0:
        parser.error("Invalid sample counts or timeout")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", args.device): parser.error("Invalid device identifier")
    if args.run_dir.exists() and not args.resume:
        raise ValueError("Use a fresh result directory")
    args.run_dir.mkdir(parents=True, exist_ok=args.resume)
    run_id = "r" + uuid.uuid4().hex[:12]
    if len(set(args.schemes)) != len(args.schemes): parser.error("Duplicate scheme")
    cells = [cell for scheme in args.schemes for cell in plan(run_id) if cell["scheme"] == scheme]
    manifest = {"state": "planned", "run_id": run_id, "created_utc": datetime.now(timezone.utc).isoformat(),
                "iterations": args.iterations, "warmups": args.warmups, "cells": cells,
                "transport": "device Internet -> test DNS -> hk SNI:443; no adb reverse",
                "timing": "time to acceptance/rejection; HTTP response reading separate",
                "record_transport_failures": args.record_transport_failures,
                "ordering_limit": "fixed scheme order; reboot before compatibility group to clear RAM, not protected rollback state"}
    manifest_path = args.run_dir / "matrix.json"
    completed_before = 0
    if args.resume:
        manifest = json.loads(manifest_path.read_text())
        if (manifest["state"] != "failed" or manifest["iterations"] != args.iterations
                or manifest["warmups"] != args.warmups):
            raise ValueError("Resume requires a failed run with identical sample counts")
        manifest.setdefault("failures", []).append({"error": manifest.get("error"),
            "completed_cells": manifest.get("completed_cells", 0), "resumed_utc": datetime.now(timezone.utc).isoformat()})
        manifest.pop("error", None)
        completed_before = manifest.get("completed_cells", 0)
        cells = manifest["cells"]
    def save(): manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    save()
    if args.plan_only:
        print(f"Planned {len(cells)} cells; no device/server operations")
        return
    device_lock = open("/tmp/aspin-benchmark-" + args.device + ".lock", "a")
    try:
        fcntl.flock(device_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError("Another ASPin experiment is using this device")
    deployment = json.loads(args.deployment.read_text())
    alias, remote, unit = deployment["ssh_alias"], Path(deployment["remote_dir"]), deployment["origin_unit"]
    if remote.parent != Path("/opt/aspin-experiment") or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", alias):
        raise ValueError("Unexpected remote deployment directory")
    def adb(*arguments, check=True): return run(["adb", "-s", args.device, *arguments], check)
    def ssh(*arguments): return run(["ssh", "-o", "BatchMode=yes", alias, shlex.join(map(str, arguments))])
    def device_preflight():
        if "Service aspin: found" not in adb("shell", "service", "check", "aspin"):
            raise RuntimeError("Refusing to test: OS-level ASPin service is absent")
        if adb("shell", "getprop", "ro.build.user").strip() != "exp":
            raise RuntimeError("Refusing to test: expected newly built exp image")
        if adb("shell", "getprop", "ro.product.vendor.device").strip() != "shiba":
            raise RuntimeError("Expected Pixel 8 / shiba")
        adb("root")
        adb("wait-for-device")
        if adb("shell", "id", "-u").strip() != "0":
            raise RuntimeError("Userdebug adb root is required for controlled DCP cache settings")
    device_preflight()
    original_stayon = adb("shell", "settings", "get", "global", "stay_on_while_plugged_in").strip()
    def restore_power():
        if original_stayon == "null": adb("shell", "settings", "delete", "global", "stay_on_while_plugged_in", check=False)
        else: adb("shell", "settings", "put", "global", "stay_on_while_plugged_in", original_stayon, check=False)
    atexit.register(restore_power)
    adb("shell", "svc", "power", "stayon", "true")
    adb("shell", "input", "keyevent", "KEYCODE_WAKEUP")
    adb("shell", "wm", "dismiss-keyguard")
    wait_for_internet(adb, "es256.idouzi.top")
    if adb("reverse", "--list").strip():
        raise RuntimeError("Remove adb reverse mappings before a direct Internet experiment")
    manifest["device"] = {key: adb("shell", "getprop", key).strip() for key in
        ("ro.build.fingerprint", "ro.build.user", "ro.build.date.utc", "ro.build.version.incremental")}
    manifest["apk_sha256"] = {item.name: hashlib.sha256(item.read_bytes()).hexdigest()
                              for item in args.apk_dir.glob("ASPin-*.apk")}
    manifest["state"] = "running"
    manifest["power_control"] = "screen kept awake while externally powered; original setting restored on exit"
    # Journald uses the server's clock, not the host's. Unique generation tags
    # exclude old runs; a one-minute margin also covers sub-second truncation.
    manifest["server_audit_since_utc"] = ssh("date", "-u", "--date=1 minute ago", "+%Y-%m-%dT%H:%M:%SZ").strip()
    save()
    summaries = []
    previous_scheme = None
    try:
        for index, cell in enumerate(cells, 1):
            if index <= completed_before:
                with (args.run_dir / (cell["scenario"] + ".csv")).open() as stream:
                    rows = list(csv.DictReader(stream))
                expected = validate(rows, cell, args.iterations, args.record_transport_failures)
                audit = json.loads((args.run_dir / (cell["scenario"] + ".audit.json")).read_text())
                if audit["business_requests"] != audit["expected_business_requests"]:
                    raise ValueError("Previously completed cell lacks its audit")
                values = sorted(float(row["Outcome_ms"]) for row in rows if row["Outcome"] == expected)
                summaries.append({key: cell[key] for key in ("scheme", "algorithm", "phase", "cache")} | {
                    "attempts": len(rows), "samples": len(values), "transport_failures": len(rows)-len(values),
                    "mean_ms": statistics.mean(values),
                    **{f"p{p}_ms": values[max(0, (len(values)*p+99)//100-1)] for p in (50,95,99)},
                    "outcome": expected, "result": "PASS" if len(values)==len(rows) else "TRANSPORT_FAILURES"})
                previous_scheme = cell["scheme"]
                continue
            if cell["scheme"] == "ASPin-compatible" and previous_scheme != cell["scheme"]:
                # A fresh manifest does not erase K_a's live OS cache. Reboot clears only
                # RAM tokens so this group actually measures K_s, retaining all H_k/H_c.
                adb("reboot")
                adb("wait-for-device")
                deadline = time.monotonic() + 240
                while adb("shell", "getprop", "sys.boot_completed").strip() != "1":
                    if time.monotonic() > deadline: raise TimeoutError("Reboot did not complete")
                    time.sleep(2)
                device_preflight()
                adb("shell", "input", "keyevent", "KEYCODE_WAKEUP")
                adb("shell", "wm", "dismiss-keyguard")
                wait_for_internet(adb, "es256.idouzi.top")
            previous_scheme = cell["scheme"]
            host = cell["algorithm"] + ".idouzi.top"
            ssh("python3", remote / "control.py", "--state", remote / "state.json", "--host", "all",
                "--phase", cell["phase"], "--mode", "compat" if cell["mode"] == "compatible" else "primary",
                "--fault", "none", "--generation", cell["scenario"])
            adb("uninstall", PACKAGE, check=False)
            apk = args.apk_dir / ("ASPin-" + cell["algorithm"] + cell["suffix"] + ".apk")
            adb("install", "-r", apk)
            adb("shell", "setprop", "debug.aspin.dcp_cold", "1" if cell["scheme"] == "DCP" and cell["cache"] == "cold-forced-refresh" else "0")
            destination = args.run_dir / (cell["scenario"] + ".csv")
            private_file = "/data/user/0/" + PACKAGE + "/files/" + destination.name
            adb("logcat", "-c")
            command = ["shell", "am", "start", "-S", "-W", "-n", PACKAGE + "/.MainActivity",
                "--es", "benchmark_type", "schemecomparison", "--es", "output_csv", private_file,
                "--es", "scheme", cell["scheme"], "--es", "phase", cell["phase"],
                "--es", "policy_cache", cell["cache"], "--es", "scenario", cell["scenario"],
                "--ei", "iterations", str(args.iterations), "--ei", "warmups", str(args.warmups)]
            print(f"[{index}/{len(cells)}] {cell['scenario']}", flush=True)
            adb(*command)
            deadline = time.monotonic() + args.timeout
            relative = "files/" + destination.name
            while True:
                data = adb("exec-out", "run-as", PACKAGE, "cat", relative, check=False)
                if data.startswith("Scenario,"):
                    destination.write_text(data)
                    break
                logs = adb("logcat", "-d", "-s", "MainActivity:E", "*:S")
                if "Scheme comparison failed" in logs:
                    raise RuntimeError(logs[-3000:])
                if time.monotonic() >= deadline: raise TimeoutError(cell["scenario"])
                time.sleep(1)
            with destination.open() as stream: rows = list(csv.DictReader(stream))
            expected = validate(rows, cell, args.iterations, args.record_transport_failures)
            successful = [row for row in rows if row["Outcome"] == expected]
            failures = len(rows) - len(successful)
            audit_deadline = time.monotonic() + 10
            while True:
                lines = ssh("journalctl", "-u", unit, "--since", manifest["server_audit_since_utc"],
                            "-o", "cat", "--no-pager").splitlines()
                observations = []
                for line in lines:
                    try: value = json.loads(line)
                    except ValueError: continue
                    if value.get("generation") == cell["scenario"]: observations.append(value)
                valid, audit = audit_requests(observations, cell, args.iterations, args.warmups, expected,
                                             [int(row["Sample"]) for row in successful if row["App_Request_Sent"] == "true"],
                                             transport_failures=failures)
                if valid or time.monotonic() >= audit_deadline: break
                time.sleep(0.5)  # The last response can precede journald ingestion.
            destination.with_suffix(".audit.json").write_text(json.dumps(audit, indent=2) + "\n")
            if not valid: raise RuntimeError("Server request/cache audit failed: " + json.dumps(audit))
            values = sorted(float(row["Outcome_ms"]) for row in successful)
            if not values: raise RuntimeError("No expected-outcome observations in cell")
            summaries.append({key: cell[key] for key in ("scheme", "algorithm", "phase", "cache")} | {
                "attempts": len(rows), "samples": len(values), "transport_failures": failures,
                "mean_ms": statistics.mean(values),
                **{f"p{p}_ms": values[max(0, (len(values) * p + 99) // 100 - 1)] for p in (50, 95, 99)},
                "outcome": expected, "result": "PASS" if failures == 0 else "TRANSPORT_FAILURES"})
            print(f"  {len(values)}/{len(rows)} expected outcomes; {failures} transport failures; audit OK", flush=True)
            manifest["completed_cells"] = index
            save()
        manifest["state"] = "complete"
        with (args.run_dir / "summary.csv").open("w", newline="") as stream:
            writer = csv.DictWriter(stream, summaries[0].keys()); writer.writeheader(); writer.writerows(summaries)
    except BaseException as error:
        manifest["state"] = "failed"; manifest["error"] = str(error)
        raise
    finally:
        adb("shell", "setprop", "debug.aspin.dcp_cold", "0", check=False)
        restore_power()
        atexit.unregister(restore_power)
        ssh("python3", remote / "control.py", "--state", remote / "state.json", "--host", "all",
            "--phase", "real", "--mode", "primary", "--fault", "none", "--generation", "comparison-idle")
        save()


if __name__ == "__main__":
    main()
