#!/usr/bin/env python3
"""Remote functional cross-sign tests on the already-flashed ASPin image.

No flash, uninstall, clock change, protected-state reset, or OS build. Only the
isolated experiment origin and the test app are changed, then restored.
"""
import argparse
import csv
from datetime import datetime, timezone
import fcntl
import importlib.util
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

from benchmark_device_network import wait_for_internet

ROOT = Path(__file__).resolve().parent
PACKAGE = "com.cert.aspin"
HOST = "es256.idouzi.top"
CA_RESOURCES = (
    ROOT / "ASPin/es256/app/src/debug/res/raw/aspin_benchmark_ca.pem",
    ROOT / "ASPin/shared/src/main/res/raw/aspin_benchmark_ca.pem",
)


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(command, check=True):
    result = subprocess.run(list(map(str, command)), capture_output=True, text=True)
    if check and result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {command[0]}\n"
                           + result.stdout[-1500:] + result.stderr[-2000:])
    return result.stdout


def cases():
    return (
        ("incomplete-a", "chain-a.pem", "leaf.key", "direct-a.pem", True, False, "incomplete"),
        ("incomplete-b-rejected", "chain-b.pem", "leaf.key", "direct-b.pem", False, False, "incomplete"),
        ("complete-a", "chain-a.pem", "leaf.key", "direct-a.pem", True, False, "complete"),
        ("complete-b", "chain-b.pem", "leaf.key", "direct-b.pem", True, False, "complete"),
        ("same-name-rejected", "rogue-chain.pem", "rogue-leaf.key", "rogue-direct.pem", False, False, "complete"),
        ("padding-rejected", "rogue-padded-chain.pem", "rogue-leaf.key", "rogue-direct.pem", False, True, "complete"),
    )


def audit_requests(events, scenario, iterations, accepted):
    business = [event for event in events if event.get("path") == "/"
                and event.get("generation") == scenario]
    observed = [event.get("observation") for event in business]
    expected = [scenario + "-" + str(i) for i in range(iterations)] if accepted else []
    if sorted(observed) != sorted(expected) or any(event.get("status") != 200 for event in business):
        raise ValueError("Server application-request audit mismatch")
    return business


def refresh_restored_policies(deployment, directory, device):
    """Keep the original testbed usable after advancing its protected floors.

    Restore the real public-CA policy with a higher iat, never by deleting H_k/H_c.
    Only public JWS artifacts go to the already-isolated experiment origin.
    """
    signing = load("cross_sign_restoration_signing", "generate-lifecycle-artifacts.py")
    source = ROOT / "signing/es256"
    alias, remote = deployment["ssh_alias"], Path(deployment["remote_dir"])
    if remote.parent != Path("/opt/aspin-experiment"): raise ValueError("Unexpected origin")
    output = directory / "restored-policies"
    output.mkdir()
    def adb(*values): return run(["adb", "-s", device, *values])
    issued = max(int(time.time()), int(adb("shell", "date", "+%s").strip())) + 1
    for mode, prefix in (("primary", "my-app"), ("compat", "my-dcp")):
        name = "ClaimSigningKey." + mode + ".jws"
        payload = signing.decode_payload(source / name)
        payload.update(iat=issued, exp=issued + 3600)
        (output / name).write_text(signing.general_jws(payload, [(
            source / (prefix + "-key.pem"), source / (prefix + "-pubkey.pem"), "ES256")]))
    payload = signing.decode_payload(source / "ServerCertClaim.jws")
    payload.update(iat=issued, exp=issued + 3600)
    (output / "ServerCertClaim.jws").write_text(signing.general_jws(payload, [(
        source / "my-claim-key.pem", source / "my-claim-pubkey.pem", "ES256")]))
    for path in output.glob("*.jws"):
        run(["scp", "-q", path, f"{alias}:{remote}/tokens/es256/{path.name}"])
    while int(adb("shell", "date", "+%s").strip()) < issued: time.sleep(1)
    private = "/data/user/0/" + PACKAGE + "/files/cross-sign-restored-" + str(issued) + ".csv"
    adb("shell", "am", "start", "-S", "-W", "-n", PACKAGE + "/.MainActivity",
        "--es", "benchmark_type", "claimprobe", "--es", "output_csv", private,
        "--es", "probe_label", "cross-sign-restored", "--ez", "expect_success", "true",
        "--ez", "force_refresh", "true")
    deadline = time.monotonic() + 60
    while True:
        raw = run(["adb", "-s", device, "exec-out", "run-as", PACKAGE, "cat", private], check=False)
        if raw.startswith("Label,"):
            (output / "claimprobe.csv").write_text(raw)
            rows = list(csv.DictReader(raw.splitlines()))
            if len(rows) != 1 or rows[0]["Result"] != "PASS" or rows[0]["ObservedSuccess"] != "true":
                raise ValueError("Restored public-CA claim lookup failed")
            return
        if time.monotonic() > deadline: raise TimeoutError("Restoration claim probe")
        time.sleep(0.5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", default="3A201FDJH000GP")
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--restore-apk", type=Path, default=ROOT / "results/apks/ASPin-es256.apk")
    args = parser.parse_args()
    if args.iterations < 1 or args.iterations > 100:
        parser.error("iterations must be in [1, 100]")
    if args.run_dir.exists():
        parser.error("Use a new result directory; failed runs are retained, never overwritten")
    if not args.restore_apk.is_file():
        parser.error("A known original APK is required for restoration")
    deployment = json.loads(args.deployment.read_text())
    alias, remote = deployment["ssh_alias"], Path(deployment["remote_dir"])
    unit = deployment["origin_unit"]
    if remote.parent != Path("/opt/aspin-experiment") or not unit.startswith("aspin-origin-"):
        raise ValueError("Only an isolated ASPin experiment origin is supported")
    lock = open("/tmp/aspin-benchmark-" + args.device + ".lock", "a")
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    args.run_dir.mkdir(parents=True)
    args.run_dir = args.run_dir.resolve()
    def adb(*values, check=True): return run(["adb", "-s", args.device, *values], check)
    def ssh(*values): return run(["ssh", "-o", "BatchMode=yes", alias, shlex.join(map(str, values))])
    def copy_to(source, destination): run(["scp", "-q", source, f"{alias}:{destination}"])
    if "Service aspin: found" not in adb("shell", "service", "check", "aspin"):
        raise RuntimeError("The device must already run the ASPin GSI")
    if adb("shell", "getprop", "ro.build.user").strip() != "exp":
        raise RuntimeError("Unexpected image build user")
    if adb("reverse", "--list").strip():
        raise RuntimeError("Remove existing adb reverse mappings before this remote experiment")
    adb("root"); adb("wait-for-device")
    original_power = adb("shell", "settings", "get", "global", "stay_on_while_plugged_in").strip()
    original_manifest = ssh("cat", remote / "manifest.json")
    original_state = ssh("cat", remote / "state.json")
    (args.run_dir / "origin-manifest-before.json").write_text(original_manifest)
    (args.run_dir / "origin-state-before.json").write_text(original_state)
    manifest = {"state": "running", "run_id": "cs" + uuid.uuid4().hex[:12],
                "created_utc": datetime.now(timezone.utc).isoformat(), "cells": [],
                "iterations": args.iterations, "hostname": HOST, "restored": False,
                "device_fingerprint": adb("shell", "getprop", "ro.build.fingerprint").strip(),
                "scope": "controlled test roots, functional observations; not public-CA cross-sign latency"}
    def save():
        (args.run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    save()
    remote_changed = False
    installed = False
    backups = {path: path.read_bytes() for path in CA_RESOURCES}
    signing = load("cross_sign_signing", "generate-lifecycle-artifacts.py")
    fixture_module = load("cross_sign_generator", "generate-cross-sign-fixtures.py")
    validator = load("cross_sign_validator", "summarize-lifecycle-results.py")
    remote_fixture = remote / "cross-sign" / manifest["run_id"]
    try:
        adb("shell", "svc", "power", "stayon", "true")
        adb("shell", "input", "keyevent", "KEYCODE_WAKEUP")
        adb("shell", "wm", "dismiss-keyguard")
        wait_for_internet(adb, HOST)
        with tempfile.TemporaryDirectory(prefix="aspin-cross-sign-") as temporary:
            fixtures = Path(temporary) / "fixtures"
            fixture_module.generate(fixtures, HOST)
            saved_fixtures = args.run_dir / "artifacts/cross-sign"
            saved_fixtures.mkdir(parents=True)
            for source in fixtures.glob("*.pem"):
                shutil.copyfile(source, saved_fixtures / source.name)
            for mode, prefix in (("primary", "my-app"), ("compatible", "my-dcp")):
                shutil.copyfile(ROOT / "signing/es256" / (prefix + "-pubkey.pem"),
                                saved_fixtures / (mode + "-root.pem"))
            for path, original in backups.items():
                path.write_bytes(original + b"\n" + (fixtures / "trusted-roots.pem").read_bytes())
            print("Building two debug APKs with both controlled roots; 24 workers", flush=True)
            build = subprocess.run([sys.executable, str(ROOT / "gen-signed-apks.py"),
                                    "--workers", "24", "--variant", "es256", "--mode", "primary",
                                    "--mode", "compatible", "--output-dir", str(args.run_dir / "apks")], cwd=ROOT)
            if build.returncode: raise RuntimeError("Cross-sign APK build failed")
            for path, original in backups.items(): path.write_bytes(original)
            ssh("install", "-d", "-m", "700", remote_fixture)
            for filename in ("chain-a.pem", "chain-b.pem", "rogue-chain.pem",
                             "rogue-padded-chain.pem", "leaf.key", "rogue-leaf.key"):
                copy_to(fixtures / filename, remote_fixture / filename)
            ssh("chmod", "600", remote_fixture / "leaf.key", remote_fixture / "rogue-leaf.key")
            since = ssh("date", "-u", "+%Y-%m-%dT%H:%M:%SZ").strip()
            for mode, suffix in (("primary", ""), ("compatible", "-compatible")):
                apk = args.run_dir / "apks" / ("ASPin-es256" + suffix + ".apk")
                adb("install", "-r", apk); installed = True
                # A fresh signed iat, not cache deletion or a clock rollback.
                issued = max(int(time.time()), int(adb("shell", "date", "+%s").strip()))
                prefix = "my-app" if mode == "primary" else "my-dcp"
                directory = ROOT / "signing/es256"
                delegated_jwk = json.loads((directory / "my-claim-pubkey.jwk").read_text())
                root_signer = [(directory / (prefix + "-key.pem"), directory / (prefix + "-pubkey.pem"), "ES256")]
                claim_signer = [(directory / "my-claim-key.pem", directory / "my-claim-pubkey.pem", "ES256")]
                subject, sans = signing.cert_identity(fixtures / "leaf.pem")
                tokens = {"key": signing.general_jws({"cnf": {"jwk": delegated_jwk},
                                                      "iat": issued, "exp": issued + 3600}, root_signer)}
                for kind, issuers in (("incomplete", ["direct-a.pem"]), ("complete", ["direct-a.pem", "direct-b.pem"])):
                    tokens[kind] = signing.general_jws({"subject": subject, "san": sans,
                        "issuer": [signing.issuer_id(fixtures / name) for name in issuers],
                        "iat": issued + (kind == "complete"), "exp": issued + 3600}, claim_signer)
                names = {}
                for kind, content in tokens.items():
                    path = args.run_dir / (mode + "-" + kind + ".jws")
                    path.write_text(content)
                    names[kind] = manifest["run_id"] + "-" + path.name
                    copy_to(path, remote / "tokens/es256" / names[kind])
                while int(adb("shell", "date", "+%s").strip()) < issued + 1: time.sleep(1)
                for name, chain, key, direct, accepted, padded, policy_kind in cases():
                    scenario = manifest["run_id"] + "-" + mode + "-" + name
                    print(scenario, flush=True)
                    selected = json.loads(original_manifest)
                    selected["hosts"][HOST]["certificates"]["real"] = {
                        "chain": str((remote_fixture / chain).relative_to(remote)),
                        "key": str((remote_fixture / key).relative_to(remote))}
                    pending = args.run_dir / "origin-active.json"
                    pending.write_text(json.dumps(selected))
                    remote_changed = True
                    copy_to(pending, remote / "manifest.json")
                    ssh("python3", remote / "control.py", "--state", remote / "state.json", "--host", HOST,
                        "--phase", "real", "--mode", "primary" if mode == "primary" else "compat", "--fault", "none",
                        "--key-file", names["key"], "--claim-file", names[policy_kind], "--generation", scenario)
                    ssh("systemctl", "restart", unit)
                    ssh("systemctl", "is-active", "--quiet", unit)
                    private = "/data/user/0/" + PACKAGE + "/files/" + scenario + ".csv"
                    command = ["shell", "am", "start", "-S", "-W", "-n", PACKAGE + "/.MainActivity",
                        "--es", "benchmark_type", "crosssign", "--es", "scenario", scenario,
                        "--ei", "iterations", str(args.iterations), "--ez", "expect_success", str(accepted).lower(),
                        "--es", "expected_issuer_id", validator.certificate_id(fixtures / direct),
                        "--es", "output_csv", private]
                    if padded: command.extend(["--es", "expected_extra_id", validator.certificate_id(fixtures / "direct-a.pem")])
                    adb("logcat", "-c"); adb(*command)
                    deadline = time.monotonic() + 180
                    output = args.run_dir / (mode + "-" + name + ".csv")
                    while True:
                        raw = adb("exec-out", "run-as", PACKAGE, "cat", "files/" + scenario + ".csv", check=False)
                        if raw.startswith("Scenario,"): output.write_text(raw); break
                        errors = adb("logcat", "-d", "-s", "MainActivity:E", "*:S")
                        if "Cross-sign test failed" in errors: raise RuntimeError(errors[-3000:])
                        if time.monotonic() > deadline: raise TimeoutError("Missing cross-sign CSV: " + errors[-2000:])
                        time.sleep(0.5)
                    with output.open(newline="") as stream: rows = list(csv.DictReader(stream))
                    if len(rows) != args.iterations: raise ValueError("Incomplete cross-sign attempts")
                    validator.validate_cross_sign(rows, "cross-sign-" + name + ".csv", args.run_dir)
                    events = []
                    for line in ssh("journalctl", "-u", unit, "--since", since, "-o", "cat", "--no-pager").splitlines():
                        try: events.append(json.loads(line))
                        except ValueError: continue
                    business = audit_requests(events, scenario, args.iterations, accepted)
                    output.with_suffix(".audit.json").write_text(json.dumps(business, indent=2) + "\n")
                    manifest["cells"].append({"mode": mode, "case": name, "scenario": scenario,
                        "file": output.name, "policy": policy_kind, "accepted": accepted, "result": "PASS"})
                    save()
            manifest["state"] = "complete"
    except BaseException as error:
        manifest.update(state="failed", error=str(error))
        raise
    finally:
        errors = []
        for path, original in backups.items(): path.write_bytes(original)
        if remote_changed:
            try:
                copy_to(args.run_dir / "origin-manifest-before.json", remote / "manifest.json")
                copy_to(args.run_dir / "origin-state-before.json", remote / "state.json")
                ssh("systemctl", "restart", unit)
                ssh("systemctl", "is-active", "--quiet", unit)
            except Exception as error: errors.append("origin restoration: " + str(error))
        if installed:
            try:
                adb("install", "-r", args.restore_apk)
                if not errors: refresh_restored_policies(deployment, args.run_dir, args.device)
            except Exception as error: errors.append("app restoration: " + str(error))
        try:
            if original_power == "null": adb("shell", "settings", "delete", "global", "stay_on_while_plugged_in")
            else: adb("shell", "settings", "put", "global", "stay_on_while_plugged_in", original_power)
        except Exception as error: errors.append("power restoration: " + str(error))
        manifest["restored"] = not errors
        if errors: manifest.update(state="failed", cleanup_errors=errors)
        save()
    if manifest["state"] != "complete": raise RuntimeError("Restoration incomplete")
    print("Completed 12 cross-sign cells; run summarize-cross-sign-results.py for independent checks", flush=True)


if __name__ == "__main__":
    main()
