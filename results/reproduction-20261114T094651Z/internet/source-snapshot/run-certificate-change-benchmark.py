#!/usr/bin/env python3
"""Same-issuer certificate renewal/TLS rekeying on the ASPin-flashed Pixel 8.

Uses the existing isolated hk origin and SNI routing. Restores its manifest,
state, and server code on exit. Never changes DNS records, flashes, clears protected
state, moves the clock, or uploads app/claim/manifest-root private keys.
"""
import argparse
import atexit
import base64
from datetime import datetime, timezone
import fcntl
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
import csv

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from jwcrypto import jwk, jws

from benchmark_device_network import wait_for_internet

ROOT = Path(__file__).resolve().parent
PACKAGE = "com.cert.aspin"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


comparison = load("certificate_change_comparison", "run-remote-comparison.py")
fixtures = load("certificate_change_fixtures", "prepare-certificate-change.py")
signing = load("certificate_change_signing", "generate-lifecycle-artifacts.py")
dcp = load("certificate_change_dcp", "signing/gen_dcp_policy.py")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def plan(prefix):
    cells = []
    for scheme in ("TLS", "SCP", "DCP", "ASPin", "ASPin-compatible"):
        mode, suffix, _ = comparison.MODES[scheme]
        cache = "none" if scheme == "TLS" else "static" if scheme == "SCP" else "hot"
        for phase in fixtures.PHASES:
            cells.append({"scheme": scheme, "mode": mode, "suffix": suffix,
                "phase": phase, "cache": cache, "algorithm": "es256",
                "scenario": prefix + "-" + scheme.lower() + "-" + phase,
                "reuse_cached_policy": scheme.startswith("ASPin") and phase != "real"})
    return cells


def prepare_policies(output, certificates, lifetime=86400):
    """One immutable pair per root; same T_c and DCP leaf pin at every stage."""
    output.mkdir(parents=True, exist_ok=False)
    directory = ROOT / "signing/es256"
    issued = int(time.time())
    delegated = jwk.JWK.from_pem((directory / "my-claim-pubkey.pem").read_bytes())
    payload = {"cnf": {"jwk": json.loads(delegated.export_public())},
               "iat": issued, "exp": issued + lifetime}
    for mode, stem in (("primary", "my-app"), ("compat", "my-dcp")):
        value = signing.general_jws(payload, [(directory / (stem + "-key.pem"),
            directory / (stem + "-pubkey.pem"), "ES256")])
        (output / ("ClaimSigningKey." + mode + ".jws")).write_text(value + "\n")
    leaf = x509.load_pem_x509_certificate((certificates / "real/leaf.pem").read_bytes())
    chain = x509.load_pem_x509_certificates((certificates / "real/fullchain.pem").read_bytes())
    issuer = "sha256:" + signing.b64url(hashlib.sha256(
        chain[1].public_bytes(serialization.Encoding.DER)).digest())
    claim = {"subject": leaf.subject.rfc4514_string(), "san": fixtures.names(leaf),
             "issuer": [issuer], "iat": issued, "exp": issued + lifetime}
    (output / "ServerCertClaim.jws").write_text(signing.general_jws(claim, [(
        directory / "my-claim-key.pem", directory / "my-claim-pubkey.pem", "ES256")]) + "\n")
    (output / "DCPServerCertPin.jws").write_text(dcp.generate(
        ROOT, "es256", certificates / "real/leaf.pem", lifetime, issued))
    return issued


def audit_policies(output, certificates):
    directory = ROOT / "signing/es256"
    verified = {}
    for mode, stem in (("primary", "my-app"), ("compat", "my-dcp")):
        token = jws.JWS()
        token.deserialize((output / ("ClaimSigningKey." + mode + ".jws")).read_text())
        token.verify(jwk.JWK.from_pem((directory / (stem + "-pubkey.pem")).read_bytes()))
        key_payload = json.loads(token.payload)
        token.deserialize((output / "ServerCertClaim.jws").read_text())
        token.verify(jwk.JWK(**key_payload["cnf"]["jwk"]))
        claim = json.loads(token.payload)
        if not all(0 < p["iat"] < p["exp"] for p in (key_payload, claim)):
            raise ValueError("Invalid signed intervals")
        verified[mode] = claim
    if verified["primary"] != verified["compat"]:
        raise ValueError("ASPin roots must authenticate the same issuer policy")
    leaf = x509.load_pem_x509_certificate((certificates / "real/leaf.pem").read_bytes())
    issuer = x509.load_pem_x509_certificates((certificates / "real/fullchain.pem").read_bytes())[1]
    wanted = "sha256:" + signing.b64url(hashlib.sha256(
        issuer.public_bytes(serialization.Encoding.DER)).digest())
    claim = verified["primary"]
    if (claim["subject"] != leaf.subject.rfc4514_string()
            or claim["san"] != fixtures.names(leaf) or claim["issuer"] != [wanted]):
        raise ValueError("ASPin policy differs from the fixed baseline identity/issuer")
    token = jws.JWS()
    token.deserialize((output / "DCPServerCertPin.jws").read_text())
    token.verify(jwk.JWK.from_pem((directory / "my-dcp-pubkey.pem").read_bytes()))
    pin = json.loads(token.payload)
    if (pin["hostname"] != fixtures.names(leaf)[0]
            or pin["pins"] != ["sha256:" + signing.b64url(hashlib.sha256(fixtures.spki(leaf)).digest())]):
        raise ValueError("Independent DCP must retain the original leaf SPKI")
    scp = certificates.parent / "scp-res/xml/network_security_config.xml"
    if not scp.is_file():
        scp = ROOT / "ASPin/es256/app/src/scpBenchmark/res/xml/network_security_config.xml"
    import xml.etree.ElementTree as ET
    pins = [p.text.strip() for p in ET.parse(scp).iter("pin")]
    if pins != [base64.b64encode(hashlib.sha256(fixtures.spki(leaf)).digest()).decode()]:
        raise ValueError("SCP configuration does not pin the baseline leaf SPKI")
    return {p.name: digest(p) for p in output.glob("*.jws")}


def run(command, check=True):
    return subprocess.run(list(map(str, command)), check=check,
                          capture_output=True, text=True).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", default="3A201FDJH000GP")
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--warmups", type=int, default=3)
    args = parser.parse_args()
    directory = args.run_dir.resolve()
    if args.iterations < 1 or args.warmups < 0 or (directory / "manifest.json").exists():
        raise ValueError("Use a fresh run with positive observation counts")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", args.device):
        raise ValueError("Invalid device identifier")
    directory.mkdir(parents=True, exist_ok=True)
    device_lock = open("/tmp/aspin-benchmark-" + args.device + ".lock", "a")
    fcntl.flock(device_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    certificates = directory / "certificates"
    certificate_records = fixtures.inspect_fixtures(certificates)
    hostname = certificate_records["real"]["san"][0]
    if hostname != "es256.idouzi.top":
        raise ValueError("This test APK/profile inventory is specifically ES256")
    issued = prepare_policies(directory / "policies", certificates)
    policy_hashes = audit_policies(directory / "policies", certificates)
    deployment = json.loads(args.deployment.read_text())
    alias, remote, unit = deployment["ssh_alias"], Path(deployment["remote_dir"]), deployment["origin_unit"]
    if (remote.parent != Path("/opt/aspin-experiment")
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", alias)
            or not re.fullmatch(r"aspin-origin-[A-Za-z0-9._-]+", unit)):
        raise ValueError("Unexpected isolated test deployment")
    def adb(*values, check=True):
        return run(["adb", "-s", args.device, *values], check)
    def ssh(*values):
        return run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", alias,
                    shlex.join(map(str, values))])
    if ("Service aspin: found" not in adb("shell", "service", "check", "aspin")
            or adb("shell", "getprop", "ro.build.user").strip() != "exp"
            or adb("shell", "getprop", "ro.product.vendor.device").strip() != "shiba"
            or adb("reverse", "--list").strip()):
        raise RuntimeError("An ASPin exp Pixel 8 with a direct Internet path is required")
    adb("root"); adb("wait-for-device")
    fingerprint = adb("shell", "getprop", "ro.build.fingerprint").strip()
    original_power = adb("shell", "settings", "get", "global", "stay_on_while_plugged_in").strip()
    original_cold = adb("shell", "getprop", "debug.aspin.dcp_cold").strip()
    def restore_device_settings():
        adb("shell", "setprop", "debug.aspin.dcp_cold", original_cold or "0", check=False)
        if original_power == "null":
            adb("shell", "settings", "delete", "global", "stay_on_while_plugged_in", check=False)
        else:
            adb("shell", "settings", "put", "global", "stay_on_while_plugged_in", original_power, check=False)
    atexit.register(restore_device_settings)
    adb("shell", "svc", "power", "stayon", "true")
    adb("shell", "input", "keyevent", "KEYCODE_WAKEUP")
    adb("shell", "wm", "dismiss-keyguard")
    wait_for_internet(adb, hostname)
    while int(adb("shell", "date", "+%s").strip()) < issued:
        time.sleep(1)
    run_id = "c" + uuid.uuid4().hex[:12]
    cells = plan(run_id)
    manifest = {"state": "running", "run_id": run_id,
        "created_utc": datetime.now(timezone.utc).isoformat(), "device_fingerprint": fingerprint,
        "transport": "Pixel 8 Wi-Fi Internet to public-CA HTTPS origin",
        "hostname": hostname, "iterations": args.iterations, "warmups": args.warmups,
        "certificates": certificate_records, "policy_sha256": policy_hashes, "cells": cells,
        "completed_cells": 0, "scope": "ES256 functional observations, fixed order; not a latency comparison",
        "protected_state_reset": False, "clock_changed": False, "dns_records_changed": False,
        "dns_server_override": os.environ.get('ASPIN_BENCHMARK_DNS'),
        "scp_resource_sha256": digest(directory / "scp-res/xml/network_security_config.xml"),
        "source_sha256": {name: digest(ROOT / name) for name in (
            "run-certificate-change-benchmark.py", "prepare-certificate-change.py",
            "remote-experiment/server.py", "remote-experiment/control.py",
            "ASPin/shared/src/main/java/com/cert/aspin/SchemeComparisonBenchmark.java",
            "ASPin/shared/src/main/java/com/cert/aspin/RttBenchmarkChecks.java")},
        "apk_sha256": {p.name: digest(p) for p in (directory / "apks").glob("ASPin-*.apk")}}
    if set(manifest["apk_sha256"]) != {"ASPin-es256" + suffix + ".apk" for suffix in ("", "-scp", "-dcp", "-compatible")}:
        raise ValueError("All four experiment APKs are required")
    def save():
        (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    save()
    backup = directory / "deployment-before"
    backup.mkdir()
    originals = {}
    trial = remote / ("certificate-change-" + run_id)
    modified = False
    def control(cell, generation):
        mode = "compat" if cell["mode"] == "compatible" else "primary"
        ssh("python3", remote / "control.py", "--state", remote / "state.json", "--host", hostname,
            "--phase", cell["phase"], "--mode", mode, "--fault", "none",
            "--key-file", "ClaimSigningKey." + mode + ".jws", "--claim-file", "ServerCertClaim.jws",
            "--dcp-file", "DCPServerCertPin.jws", "--generation", generation)
    try:
        for filename in ("manifest.json", "state.json", "server.py", "control.py"):
            original = ssh("cat", remote / filename)
            originals[filename] = original
            (backup / filename).write_text(original)
        active = json.loads(originals["manifest.json"])
        entry = active["hosts"][hostname]
        relative = trial.relative_to(remote)
        entry["tokens"] = str(relative / "tokens")
        entry["certificates"].update({phase: {
            "chain": str(relative / "certificates" / phase / "fullchain.pem"),
            "key": str(relative / "certificates" / phase / "tls-key.pem")} for phase in fixtures.PHASES})
        active_path = directory / "deployment-active.json"
        active_path.write_text(json.dumps(active, indent=2) + "\n")
        with tempfile.TemporaryDirectory(prefix="aspin-certificate-change-") as temporary:
            bundle = Path(temporary) / "bundle.tar.gz"
            with tarfile.open(bundle, "w:gz") as archive:
                for phase in fixtures.PHASES:
                    for name in ("fullchain.pem", "tls-key.pem"):
                        archive.add(certificates / phase / name,
                                    arcname="certificates/" + phase + "/" + name)
                for p in (directory / "policies").glob("*.jws"):
                    archive.add(p, arcname="tokens/" + p.name)
            bundle.chmod(0o600)
            ssh("install", "-d", "-m", "0700", trial)
            run(["scp", "-q", bundle, f"{alias}:{trial}/bundle.tar.gz"])
            ssh("tar", "--no-same-owner", "-xzf", trial / "bundle.tar.gz", "-C", trial)
            ssh("rm", "--", trial / "bundle.tar.gz")
        # All backups are complete before modifying the existing isolated origin.
        modified = True
        for filename in ("server.py", "control.py"):
            run(["scp", "-q", ROOT / "remote-experiment" / filename, f"{alias}:{remote}/{filename}"])
        run(["scp", "-q", active_path, f"{alias}:{remote}/manifest.json"])
        control(cells[0], run_id + "-initial")
        ssh("systemctl", "restart", unit)
        if ssh("systemctl", "is-active", unit).strip() != "active":
            raise RuntimeError("Isolated origin failed to start")
        manifest["server_since"] = ssh("date", "-u", "--date=1 minute ago", "+%Y-%m-%dT%H:%M:%SZ").strip()
        previous_scheme = None
        for index, cell in enumerate(cells, 1):
            if previous_scheme != cell["scheme"]:
                if cell["scheme"] == "ASPin-compatible":
                    adb("reboot"); adb("wait-for-device")
                    deadline = time.monotonic() + 240
                    while adb("shell", "getprop", "sys.boot_completed").strip() != "1":
                        if time.monotonic() > deadline: raise TimeoutError("Cache-isolating reboot")
                        time.sleep(2)
                    adb("root"); adb("wait-for-device")
                    adb("shell", "input", "keyevent", "KEYCODE_WAKEUP")
                    adb("shell", "wm", "dismiss-keyguard")
                    wait_for_internet(adb, hostname)
                adb("uninstall", PACKAGE, check=False)
                adb("install", directory / "apks" / ("ASPin-es256" + cell["suffix"] + ".apk"))
                adb("shell", "setprop", "debug.aspin.dcp_cold", "0")
                previous_scheme = cell["scheme"]
            label = cell["scenario"]
            control(cell, label + "-preflight")
            connection = http.client.HTTPSConnection(hostname, timeout=20,
                                                     context=ssl.create_default_context())
            connection.connect()
            peer = connection.sock.getpeercert(binary_form=True)
            connection.close()
            if hashlib.sha256(peer).hexdigest() != certificate_records[cell["phase"]]["leaf_sha256"]:
                raise ValueError("Public endpoint presented an unexpected leaf")
            if audit_policies(directory / "policies", certificates) != policy_hashes:
                raise ValueError("Policy bytes changed between certificate stages")
            remote_hashes = ssh("sha256sum", *[trial / "tokens" / name for name in sorted(policy_hashes)])
            if {Path(line.split()[1]).name: line.split()[0] for line in remote_hashes.splitlines()} != policy_hashes:
                raise ValueError("Remote policy bytes changed")
            control(cell, label)
            output = directory / (label + ".csv")
            command = ["shell", "am", "start", "-S", "-W", "-n", PACKAGE + "/.MainActivity",
                "--es", "benchmark_type", "schemecomparison", "--es", "output_csv",
                "/data/user/0/" + PACKAGE + "/files/" + output.name]
            for key, value in (("scheme", cell["scheme"]), ("phase", cell["phase"]),
                    ("policy_cache", cell["cache"]), ("scenario", label)):
                command.extend(["--es", key, value])
            command.extend(["--ei", "iterations", str(args.iterations), "--ei", "warmups", str(args.warmups),
                            "--ez", "reuse_cached_policy", str(cell["reuse_cached_policy"]).lower()])
            print(f"[{index}/{len(cells)}] {label}", flush=True)
            adb("logcat", "-c"); adb(*command)
            deadline = time.monotonic() + 240
            while True:
                text = adb("exec-out", "run-as", PACKAGE, "cat", "files/" + output.name, check=False)
                if text.startswith("Scenario,"):
                    output.write_text(text); break
                errors = adb("logcat", "-d", "-s", "MainActivity:E", "*:S")
                if "Scheme comparison failed" in errors: raise RuntimeError(errors[-2000:])
                if time.monotonic() > deadline: raise TimeoutError(label)
                time.sleep(0.5)
            with output.open() as source: rows = list(csv.DictReader(source))
            expected = comparison.validate(rows, cell, args.iterations)
            audit_deadline = time.monotonic() + 10
            while True:
                events = []
                for line in ssh("journalctl", "-u", unit, "--since", manifest["server_since"],
                                "-o", "cat", "--no-pager").splitlines():
                    try: event = json.loads(line)
                    except ValueError: continue
                    if event.get("generation") == label: events.append(event)
                valid, audit = comparison.audit_requests(events, cell, args.iterations, args.warmups, expected)
                metadata = [e for e in events if e.get("path", "").startswith("/.well-known/")]
                wanted = (1 if cell["scheme"] == "DCP" else
                          2 if cell["scheme"].startswith("ASPin") and cell["phase"] == "real" else 0)
                valid = valid and len(metadata) == wanted and all(e.get("status") == 200 for e in metadata)
                if valid or time.monotonic() >= audit_deadline: break
                time.sleep(0.5)
            audit.update(metadata_requests=len(metadata), expected_metadata_requests=wanted,
                policy_sha256=policy_hashes, presented_leaf_sha256=hashlib.sha256(peer).hexdigest(),
                events=events)
            output.with_suffix(".audit.json").write_text(json.dumps(audit, indent=2) + "\n")
            if not valid: raise ValueError("Application-request or immutable-policy/cache audit failed")
            manifest["completed_cells"] = index
            save()
            print("  Expected outcomes and server audit passed", flush=True)
        manifest["state"] = "complete"
    except BaseException as error:
        manifest.update(state="failed", error=str(error))
        raise
    finally:
        restore_error = None
        if modified:
            try:
                for filename in originals:
                    run(["scp", "-q", backup / filename, f"{alias}:{remote}/{filename}"])
                ssh("systemctl", "restart", unit)
                if ssh("systemctl", "is-active", unit).strip() != "active":
                    raise RuntimeError("Restored isolated origin is not active")
                manifest["deployment_restored"] = all(
                    ssh("cat", remote / filename) == value for filename, value in originals.items())
                if not manifest["deployment_restored"]: raise RuntimeError("Restoration hash mismatch")
            except BaseException as error:
                restore_error = error
                manifest.update(state="failed", restore_error=str(error))
        restore_device_settings()
        atexit.unregister(restore_device_settings)
        manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
        save()
        if restore_error is not None: raise restore_error
    try:
        subprocess.run([sys.executable, str(ROOT / "summarize-certificate-change-results.py"),
                        str(directory)], check=True)
    except BaseException as error:
        manifest.update(state="audit_failed", error=str(error)); save()
        raise
    print("Complete: 15 audited cells; isolated origin restored; protected state retained", flush=True)


if __name__ == "__main__":
    main()
