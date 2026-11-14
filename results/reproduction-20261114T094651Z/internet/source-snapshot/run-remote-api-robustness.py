#!/usr/bin/env python3
"""Reproduce API/concurrency/reboot/time checks using public Internet policies.

Cached API timings deliberately measure local OS calls after remote policy
authentication, not network latency. Ordinary reboot retains H_k/H_c. The
temporary ten-minute clock rollback is restored on exit and is not a claim of
rollback-resistant time. No local origin, adb reverse, or custom CA is used.
"""
import argparse
import csv
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import time
import uuid

from benchmark_device_network import wait_for_internet

ROOT = Path(__file__).resolve().parent
TARGET, CALLER = "com.cert.aspin", "com.cert.aspin.caller"
ALGORITHMS = ("es256", "es384", "rsa3072", "rsa4096")


def caller_signing_variant(target_algorithm):
    """Every cross-app timing uses a caller signed differently from its target."""
    if target_algorithm not in ALGORITHMS:
        raise ValueError("Unknown target algorithm: " + target_algorithm)
    return "es256" if target_algorithm == "es384" else "es384"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(command, check=True):
    return subprocess.run(list(map(str, command)), check=check, capture_output=True, text=True).stdout


def probe_extras(label, expected, force, expected_error):
    # adb shell does not preserve an empty argv element as an am string value.
    values = ["--es", "probe_label", label, "--ez", "expect_success", str(expected).lower(),
              "--ez", "force_refresh", str(force).lower()]
    if expected_error:
        values.extend(["--es", "expected_error", expected_error])
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", default="3A201FDJH000GP")
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--apk-dir", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--operations", type=int, default=2000)
    parser.add_argument("--cache-matrix-only", action="store_true",
                        help="Run the complete cached self/cross matrix without clock/lifecycle probes")
    parser.add_argument("--prepare", action="store_true",
                        help="Generate fresh public policies and build new target/caller APKs with 24 workers")
    parser.add_argument("--after-cohort", type=Path,
                        help="Wait for a fresh Internet cohort; stop if it fails")
    args = parser.parse_args()
    if args.operations < 100: parser.error("At least 100 cache operations required")
    if args.after_cohort:
        while True:
            try:
                previous = json.loads(args.after_cohort.read_text())
            except json.JSONDecodeError:
                time.sleep(1)  # A concurrent progress write is not a failed run.
                continue
            if previous["state"] == "complete": break
            if previous["state"] == "failed": raise RuntimeError("Preceding Internet cohort failed")
            time.sleep(5)
    args.run_dir.mkdir(parents=True, exist_ok=False)
    lock = open("/tmp/aspin-benchmark-" + args.device + ".lock", "a")
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    deployment = json.loads(args.deployment.read_text())
    alias, remote, unit = deployment["ssh_alias"], Path(deployment["remote_dir"]), deployment["origin_unit"]
    if remote.parent != Path("/opt/aspin-experiment"): raise ValueError("Unexpected deployment")
    def adb(*values, check=True): return run(["adb", "-s", args.device, *values], check)
    def ssh(*values): return run(["ssh", "-o", "BatchMode=yes", alias, shlex.join(map(str, values))])
    if "Service aspin: found" not in adb("shell", "service", "check", "aspin"):
        raise RuntimeError("ASPin image required")
    if adb("shell", "getprop", "ro.build.user").strip() != "exp" or adb("reverse", "--list").strip():
        raise RuntimeError("Expected exp image and no adb reverse")
    adb("root"); adb("wait-for-device")
    old_power = adb("shell", "settings", "get", "global", "stay_on_while_plugged_in").strip()
    old_auto = adb("shell", "settings", "get", "global", "auto_time").strip()
    clock_changed = False
    clock_start, clock_epoch = 0, 0
    manifest = {"state": "running", "created_utc": datetime.now(timezone.utc).isoformat(),
                "run_id": "a" + uuid.uuid4().hex[:12], "cases": [],
                "schema_version": 2,
                "suite": "cache-matrix" if args.cache_matrix_only else "api-robustness",
                "operations": args.operations, "cross_algorithms": list(ALGORITHMS),
                "caller_signing_variants": {alg: caller_signing_variant(alg) for alg in ALGORITHMS},
                "clock_rollback_seconds": 0 if args.cache_matrix_only else 600,
                "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "apk_sha256": {item.name: hashlib.sha256(item.read_bytes()).hexdigest()
                               for item in args.apk_dir.glob("ASPin-*.apk")},
                "transport": "device Internet -> public-CA hk:443",
                "cache_timing_scope": "local OS API calls after Internet policy authentication",
                "device_fingerprint": adb("shell", "getprop", "ro.build.fingerprint").strip(),
                "app_source_sha256": {
                    str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in (ROOT / "ASPin").glob("*/app/src/main/java/com/cert/aspin/MainActivity.java")},
                "server_since": ssh("date", "-u", "--date=1 minute ago", "+%Y-%m-%dT%H:%M:%SZ").strip()}
    def save(): (args.run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    def setting(name, value):
        if value == "null": adb("shell", "settings", "delete", "global", name, check=False)
        else: adb("shell", "settings", "put", "global", name, value, check=False)
    def restore_clock():
        nonlocal clock_changed
        if clock_changed:
            epoch = max(int(time.time()), clock_epoch + int(time.monotonic() - clock_start))
            adb("shell", "date", "-s", "@" + str(epoch))
            clock_changed = False
        setting("auto_time", old_auto)
    def interrupted(*_): raise KeyboardInterrupt("Restoring benchmark state")
    signal.signal(signal.SIGTERM, interrupted)
    def reboot():
        adb("reboot"); adb("wait-for-device")
        deadline = time.monotonic() + 240
        while adb("shell", "getprop", "sys.boot_completed").strip() != "1":
            if time.monotonic() > deadline: raise TimeoutError("Device reboot")
            time.sleep(2)
        adb("root"); adb("wait-for-device")
        adb("shell", "svc", "power", "stayon", "true")
        adb("shell", "input", "keyevent", "KEYCODE_WAKEUP")
        adb("shell", "wm", "dismiss-keyguard")
        wait_for_internet(adb, "es256.idouzi.top")
    def control(mode, label, files=None, host="all"):
        command = ["python3", remote / "control.py", "--state", remote / "state.json",
                   "--host", host, "--phase", "real", "--mode", mode, "--fault", "none", "--generation", label,
                   "--key-file", files["tk"] if files else "ClaimSigningKey." + mode + ".jws",
                   "--claim-file", files["tc"] if files else "ServerCertClaim.jws"]
        ssh(*command)
    def events(label):
        values = []
        for line in ssh("journalctl", "-u", unit, "--since", manifest["server_since"], "-o", "cat", "--no-pager").splitlines():
            try: item = json.loads(line)
            except ValueError: continue
            if item.get("generation") == label: values.append(item)
        return values
    def observe(mode, name, kind="claimprobe", caller=TARGET, files=None, expected=True,
                expected_error="", force=False, threads=1, algorithm="es256", no_metadata=False):
        label = manifest["run_id"] + "-" + mode + "-" + name
        control(mode, label, files)
        if kind == "parallelrefresh": control("primary", label, host="es384.idouzi.top")
        output = args.run_dir / (label + ".csv")
        command = ["shell", "am", "start", "-S", "-W", "-n", caller + "/com.cert.aspin.MainActivity",
                   "--es", "benchmark_type", kind, "--es", "target_hostname", algorithm + ".idouzi.top",
                   "--es", "output_csv", "/data/user/0/" + caller + "/files/" + output.name]
        if kind == "claimprobe":
            command.extend(probe_extras(label, expected, force, expected_error))
        elif kind == "concurrency":
            command.extend(["--ei", "iterations", str(args.operations), "--ei", "threads", str(threads)])
        elif kind == "parallelrefresh": command.extend(["--es", "second_host", "es384.idouzi.top"])
        print(label, flush=True)
        adb("logcat", "-c"); adb(*command)
        deadline = time.monotonic() + 180
        while True:
            data = adb("exec-out", "run-as", caller, "cat", "files/" + output.name, check=False)
            if "\n" in data and not data.startswith("run-as:"):
                output.write_text(data)
                with output.open() as stream: rows = list(csv.DictReader(stream))
                if (len(rows) == 1 and rows[0].get("Result") in ("PASS", "FAIL")
                        and all(value is not None for value in rows[0].values())):
                    break
            if time.monotonic() >= deadline:
                raise TimeoutError(label + ": " + adb("logcat", "-d", "-s", "MainActivity:E", "*:S")[-2000:])
            time.sleep(0.5)
        row = rows[0]
        if row.get("Result") != "PASS": raise ValueError(str(row))
        if kind == "claimprobe":
            if row.get("Label") != label or row.get("ObservedSuccess") != str(expected).lower():
                raise ValueError("Wrong probe result")
            if no_metadata and (float(row["Tk_ms"]) != 0 or float(row["Tc_ms"]) != 0):
                raise ValueError("Expected pure cache hit")
        elif kind == "concurrency":
            if (int(row["Operations"]) != args.operations or int(row["Threads"]) != threads
                    or int(row["Successes"]) != args.operations or int(row["Failures"]) != 0):
                raise ValueError("Incomplete concurrency evidence")
            if (row.get("API") != ("self" if caller == TARGET else "cross")
                    or row.get("Hostname") != algorithm + ".idouzi.top"
                    or row.get("TargetAppId") != TARGET):
                raise ValueError("Cached API result does not match the requested target/context")
        time.sleep(0.5)
        seen = events(label)
        metadata = [item for item in seen if item.get("path", "").startswith("/.well-known/")]
        business = [item for item in seen if item.get("path") == "/"]
        if any(item.get("observation", "").startswith(manifest["run_id"]) for item in business):
            raise ValueError("API probe sent business data")
        if no_metadata and metadata: raise ValueError("Cache probe retrieved metadata")
        audit = {"business_requests": 0, "unattributed_business_requests": business,
                 "metadata_requests": len(metadata), "events": seen}
        output.with_suffix(".audit.json").write_text(json.dumps(audit, indent=2) + "\n")
        manifest["cases"].append({"file": output.name, "mode": mode, "algorithm": algorithm,
                                  "kind": kind, "caller": caller, "result": "PASS",
                                  "caller_signing_variant": caller_signing_variant(algorithm) if caller == CALLER else algorithm})
        save()
        return row
    fixtures = load("remote_api_fixtures", "run-policy-scenario-matrix.py").Fixtures()
    def publish(mode, name):
        tk, tc, _ = fixtures.pair(mode)
        files = {}
        for kind, data in (("tk", tk), ("tc", tc)):
            path = args.run_dir / f"{mode}-{name}-{kind}.jws"
            path.write_text(data)
            run(["scp", "-q", path, f"{alias}:{remote}/tokens/es256/{path.name}"])
            files[kind] = path.name
        issued = fixtures.last
        while int(adb("shell", "date", "+%s").strip()) < issued: time.sleep(1)
        return files
    save()
    try:
        if args.prepare:
            args.apk_dir.mkdir(parents=True, exist_ok=False)
            environment = os.environ | {"JAVA_HOME": "/usr/lib/jvm/java-21-openjdk",
                                       "ASPIN_JAVA_HOME": "/usr/lib/jvm/java-21-openjdk"}
            for name, command in (
                    ("fresh-policies", [sys.executable, ROOT / "gen-trust-artifacts.py"]),
                    ("publish-policies", [sys.executable, ROOT / "update-remote-policies.py",
                                          "--deployment", args.deployment]),
                    ("build-targets-and-callers", [sys.executable, ROOT / "gen-signed-apks.py",
                         "--workers", "24", "--mode", "primary", "--mode", "compatible",
                         "--build-callers", "--output-dir", args.apk_dir])):
                print("Preparing " + name, flush=True)
                subprocess.run(list(map(str, command)), check=True, env=environment)
        manifest["apk_sha256"] = {item.name: hashlib.sha256(item.read_bytes()).hexdigest()
                                  for item in args.apk_dir.glob("ASPin-*.apk")}
        for algorithm in ALGORITHMS:
            destination = args.run_dir / "policy-artifacts" / algorithm
            destination.mkdir(parents=True)
            for name in ("ClaimSigningKey.primary.jws", "ClaimSigningKey.compat.jws", "ServerCertClaim.jws"):
                shutil.copyfile(ROOT / "signing" / algorithm / name, destination / name)
        save()
        adb("shell", "svc", "power", "stayon", "true")
        wait_for_internet(adb, "es256.idouzi.top")
        for mode, suffix in (("primary", ""), ("compat", "-compatible")):
            # A primary APK declares only K_a, and every cache group explicitly
            # authenticates a fresh pair. K_s additionally needs RAM isolation
            # from the preceding group's still-authorized K_a entries.
            if mode == "compat": reboot()
            for algorithm in ALGORITHMS:
                adb("uninstall", TARGET, check=False)
                adb("install", args.apk_dir / ("ASPin-" + algorithm + suffix + ".apk"))
                observe(mode, algorithm + "-prime", force=True, algorithm=algorithm)
                observe(mode, algorithm + "-cached-probe", no_metadata=True, algorithm=algorithm)
                for threads in (1, 8):
                    observe(mode, algorithm + f"-cache-{threads}t", kind="concurrency", threads=threads,
                            algorithm=algorithm, no_metadata=True)
                caller_apk = args.apk_dir / ("ASPin-caller-" + caller_signing_variant(algorithm) + ".apk")
                adb("uninstall", CALLER, check=False)
                adb("install", caller_apk)
                observe(mode, algorithm + "-cross-target-prime", caller=CALLER, force=True, algorithm=algorithm)
                observe(mode, algorithm + "-cross-cached-probe", caller=CALLER, algorithm=algorithm, no_metadata=True)
                for threads in (1, 8):
                    observe(mode, algorithm + f"-cross-cache-{threads}t", kind="concurrency", caller=CALLER,
                            threads=threads, algorithm=algorithm, no_metadata=True)
            if args.cache_matrix_only:
                continue
            adb("uninstall", TARGET, check=False)
            adb("install", args.apk_dir / ("ASPin-es256" + suffix + ".apk"))
            observe(mode, "parallel-host-refresh", kind="parallelrefresh")
            old, new = publish(mode, "earlier"), publish(mode, "higher")
            observe(mode, "earlier-accepted", files=old, force=True)
            observe(mode, "higher-accepted", files=new, force=True)
            reboot()
            observe(mode, "reboot-old-tc", files=new | {"tc": old["tc"]}, force=True,
                    expected=False, expected_error="anti-rollback")
            observe(mode, "reboot-old-tk", files=old | {"tc": new["tc"]}, force=True,
                    expected=False, expected_error="anti-rollback")
            observe(mode, "reboot-current", files=new, force=True)
            clock_epoch = int(adb("shell", "date", "+%s").strip())
            clock_start = time.monotonic()
            setting("auto_time", "0")
            clock_changed = True
            adb("shell", "date", "-s", "@" + str(clock_epoch - 600))
            observe(mode, "clock-rollback-600s", files=new, force=True, expected=False, expected_error="fresh")
            restore_clock()
            observe(mode, "clock-restored", files=new, force=True)
        manifest["state"] = "complete"
    except BaseException as error:
        manifest.update(state="failed", error=str(error))
        raise
    finally:
        restore_clock()
        setting("stay_on_while_plugged_in", old_power)
        control("primary", "api-idle")
        run([sys.executable, ROOT / "gen-trust-artifacts.py"])
        run([sys.executable, ROOT / "update-remote-policies.py", "--deployment", args.deployment])
        manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
        save()


if __name__ == "__main__":
    main()
