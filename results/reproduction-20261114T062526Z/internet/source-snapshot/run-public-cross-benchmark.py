#!/usr/bin/env python3
"""Public-root-only Pixel 8 tests, using one CSR issued by LE and ZeroSSL.

Adds only the requested SNI hostname; preserves unrelated routes. Never flashes,
installs roots, uninstalls packages, changes clocks, or resets protected state.
"""
import argparse
import csv
from datetime import datetime, timezone
import fcntl
import importlib.util
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET

from benchmark_device_network import wait_for_internet
import public_cross_protocol as protocol

ROOT = Path(__file__).resolve().parent
PACKAGE = "com.cert.aspin"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = load("public_cross_common", "run-cross-sign-benchmark.py")


def sni_config(original, hostname):
    """One additional SNI route; no existing route or default backend changes."""
    if not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", hostname): raise ValueError("Invalid hostname")
    if "backend aspin_public_cross" in original or hostname in original:
        raise ValueError("The requested SNI route already exists; use its saved deployment, not a duplicate")
    anchor = "    default_backend previous_tls\n"
    if original.count(anchor) != 1: raise ValueError("Unexpected shared 443 configuration")
    return original.replace(anchor,
        "    use_backend aspin_public_cross if { req_ssl_sni -i " + hostname + " }\n" + anchor) + (
        "\nbackend aspin_public_cross\n    server public_cross 127.0.0.1:18443\n")


def system_roots_only():
    config = ROOT / "ASPin/shared/src/main/res/xml/network_security_public_cross.xml"
    tree = ET.parse(config)
    sources = [node.get("src") for node in tree.findall(".//certificates")]
    if sources != ["system"] or tree.findall(".//debug-overrides"):
        raise ValueError("Public tests must use ONLY Android system roots")


def audit_public_requests(events, scenario, iterations, accepted):
    business = [event for event in events if event.get("path") == "/"
                and event.get("generation") == scenario]
    tagged = [event for event in business if event.get("observation")]
    # A fresh public hostname is visible in CT and can receive unaffiliated
    # HTTP traffic. Keep it, but never attribute an untagged request to a probe
    # which always sets X-ASPin-Observation. Wrong NONEMPTY labels still fail.
    BASE.audit_requests(tagged, scenario, iterations, accepted)
    return {"tagged": tagged, "unattributed": [event for event in business if not event.get("observation")]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment", type=Path, required=True, help="Existing isolated hk origin/SNI metadata")
    parser.add_argument("--certificate-dir", type=Path, default=ROOT / "public-cross/certificates")
    parser.add_argument("--hostname", default="cross.idouzi.top")
    parser.add_argument("--device", default="3A201FDJH000GP")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--apk-dir", type=Path)
    parser.add_argument("--restore-apk", type=Path,
                        default=ROOT / "results/apks/ASPin-es256.apk",
                        help="Primary APK to restore after the public-path scenarios")
    args = parser.parse_args()
    if args.run_dir.exists() or not 1 <= args.iterations <= 100: parser.error("Use a fresh directory and 1..100 attempts")
    if args.skip_build and not args.apk_dir: parser.error("--skip-build requires --apk-dir")
    system_roots_only()
    lock = open("/tmp/aspin-benchmark-" + args.device + ".lock", "a")
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    args.run_dir.mkdir(parents=True)
    args.run_dir = args.run_dir.resolve()
    fixture = args.run_dir / "artifacts"
    certificate_info = protocol.prepare(args.certificate_dir, fixture, args.hostname)
    existing = json.loads(args.deployment.read_text())
    alias = existing["ssh_alias"]
    reuse = existing.get("hostname") == args.hostname
    old_remote = Path(existing["sni_config_directory"] if reuse else existing["remote_dir"])
    if old_remote.parent != Path("/opt/aspin-experiment"): raise ValueError("Unexpected origin")
    def ssh(*values): return BASE.run(["ssh", "-o", "BatchMode=yes", alias, shlex.join(map(str, values))])
    def adb(*values, check=True): return BASE.run(["adb", "-s", args.device, *values], check)
    def upload(source, destination): BASE.run(["scp", "-q", source, f"{alias}:{destination}"])
    if "Service aspin: found" not in adb("shell", "service", "check", "aspin"):
        raise RuntimeError("An ASPin-flashed Pixel 8 is required")
    if adb("shell", "getprop", "ro.build.user").strip() != "exp": raise RuntimeError("Unexpected image")
    if adb("reverse", "--list").strip(): raise RuntimeError("Unexpected adb reverse mapping")
    adb("root"); adb("wait-for-device")
    tag = "public-cross-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]
    remote = Path(existing["remote_dir"]) if reuse else old_remote.parent / tag
    unit = existing["origin_unit"] if reuse else "aspin-origin-" + tag
    if remote.parent != old_remote.parent or not unit.startswith("aspin-origin-public-cross-"):
        raise ValueError("Unexpected public-origin identity")
    front_unit = json.loads(ssh("cat", old_remote / "sni-state.json"))["front_unit"]
    before_config = ssh("cat", old_remote / "haproxy.cfg")
    if reuse:
        if ("backend aspin_public_cross" not in before_config or args.hostname not in before_config
                or "server public_cross 127.0.0.1:18443" not in before_config):
            raise ValueError("Saved deployment no longer matches its SNI route")
        modified_config = before_config
    else:
        modified_config = sni_config(before_config, args.hostname)
    (args.run_dir / "haproxy-before.cfg").write_text(before_config)
    (args.run_dir / "haproxy-public-cross.cfg").write_text(modified_config)
    manifest = {"state": "running", "created_utc": datetime.now(timezone.utc).isoformat(),
        "run_id": "pc" + uuid.uuid4().hex[:12], "hostname": args.hostname, "iterations": args.iterations,
        "root_store": "Android system only", "certificate_info": certificate_info, "cells": [],
        "device_fingerprint": adb("shell", "getprop", "ro.build.fingerprint").strip(), "restored_app": False}
    def save(): (args.run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    save()
    signing = load("public_cross_signing", "generate-lifecycle-artifacts.py")
    old_power = adb("shell", "settings", "get", "global", "stay_on_while_plugged_in").strip()
    installed, routed, successful = False, False, False
    restore_apk = args.restore_apk.resolve()
    if not restore_apk.is_file(): raise RuntimeError("Known original APK required for cleanup")
    try:
        adb("shell", "svc", "power", "stayon", "true")
        adb("shell", "input", "keyevent", "KEYCODE_WAKEUP")
        adb("shell", "wm", "dismiss-keyguard")
        wait_for_internet(adb, args.hostname)
        roots = adb("exec-out", "sh", "-c",
            "cat /apex/com.android.conscrypt/cacerts/*.0 /system/etc/security/cacerts/*.0 2>/dev/null", check=False)
        if "BEGIN CERTIFICATE" not in roots: raise ValueError("Cannot archive Android system trust roots")
        (fixture / "android-system-roots.pem").write_text(roots)
        apk_dir = args.apk_dir or args.run_dir / "apks"
        if not args.skip_build:
            build = subprocess.run([sys.executable, str(ROOT / "gen-signed-apks.py"), "--workers", "24", "--variant", "es256",
                "--mode", "public-primary", "--mode", "public-compatible", "--output-dir", str(apk_dir)], cwd=ROOT)
            if build.returncode: raise RuntimeError("Public-system-roots-only APK build failed")
        ssh("install", "-d", "-m", "700", remote, remote / "tokens", remote / "certificates")
        for filename in ("le-fullchain.pem", "le-short-fullchain.pem", "zerossl-fullchain.pem", "padded-zerossl-fullchain.pem"):
            upload(fixture / filename, remote / "certificates" / filename)
        upload(args.certificate_dir / "server-privkey.pem", remote / "certificates/server-privkey.pem")
        ssh("chmod", "600", remote / "certificates/server-privkey.pem")
        for filename in ("server.py", "control.py"): upload(ROOT / "remote-experiment" / filename, remote / filename)
        origin = {"version": 1, "hosts": {args.hostname: {"algorithm": "shared-csr",
            "certificates": {"real": {"chain": "certificates/le-fullchain.pem", "key": "certificates/server-privkey.pem"},
                             "rogue": {"chain": "certificates/zerossl-fullchain.pem", "key": "certificates/server-privkey.pem"}},
            "tokens": "tokens"}}}
        origin_path, state_path = args.run_dir / "origin-manifest.json", args.run_dir / "origin-state.json"
        origin_path.write_text(json.dumps(origin))
        state_path.write_text(json.dumps({"default": {"phase": "real", "mode": "primary", "metadata_fault": "none"}, "hosts": {}}))
        upload(origin_path, remote / "manifest.json"); upload(state_path, remote / "state.json")
        if reuse:
            ssh("systemctl", "restart", unit)
        else:
            ssh("systemd-run", "--unit=" + unit, "--property=WorkingDirectory=" + str(remote),
                "--property=NoNewPrivileges=yes", "/usr/bin/python3", remote / "server.py", "--manifest", remote / "manifest.json",
                "--state", remote / "state.json", "--real-port", "18443", "--rogue-port", "19443")
            upload(args.run_dir / "haproxy-public-cross.cfg", old_remote / "haproxy-cross-pending.cfg")
            ssh("/usr/sbin/haproxy", "-c", "-f", old_remote / "haproxy-cross-pending.cfg")
            ssh("mv", "--", old_remote / "haproxy-cross-pending.cfg", old_remote / "haproxy.cfg")
            routed = True
            # HAProxy master-worker USR2 reloads with a soft-stop of old workers.
            ssh("systemctl", "kill", "--kill-whom=main", "--signal=USR2", front_unit)
        ready_code = ("import socket,ssl; s=socket.create_connection(('127.0.0.1',443),5); "
                      "t=ssl.create_default_context().wrap_socket(s,server_hostname=" + repr(args.hostname) + "); t.close()")
        for attempt in range(20):
            try: ssh("python3", "-c", ready_code); break
            except RuntimeError:
                if attempt == 19: raise
                time.sleep(0.5)
        since = ssh("date", "-u", "+%Y-%m-%dT%H:%M:%SZ").strip()
        deployment = {"ssh_alias": alias, "remote_dir": str(remote), "origin_unit": unit,
                      "front_unit": front_unit, "hostname": args.hostname, "sni_config_directory": str(old_remote)}
        (args.run_dir / "deployment.json").write_text(json.dumps(deployment, indent=2) + "\n")
        for mode, suffix in (("primary", "public-primary"), ("compatible", "public-compatible")):
            adb("install", "-r", apk_dir / ("ASPin-es256-" + suffix + ".apk")); installed = True
            source = ROOT / "signing/es256"
            prefix = "my-app" if mode == "primary" else "my-dcp"
            shutil.copyfile(source / (prefix + "-pubkey.pem"), fixture / (mode + "-root.pem"))
            issued = max(int(time.time()), int(adb("shell", "date", "+%s").strip()))
            tk = {"cnf": {"jwk": json.loads((source / "my-claim-pubkey.jwk").read_text())}, "iat": issued, "exp": issued + 3600}
            key_path = args.run_dir / (mode + "-key.jws")
            key_path.write_text(signing.general_jws(tk, [(source / (prefix + "-key.pem"), source / (prefix + "-pubkey.pem"), "ES256")]))
            upload(key_path, remote / "tokens" / key_path.name)
            subject, sans = signing.cert_identity(fixture / "le-leaf.pem")
            for index, (policy, issuers) in enumerate(certificate_info["issuer_sets"].items()):
                path = args.run_dir / (mode + "-" + policy + ".jws")
                path.write_text(signing.general_jws({"subject": subject, "san": sans, "issuer": issuers,
                    "iat": issued + index, "exp": issued + 3600}, [(source / "my-claim-key.pem", source / "my-claim-pubkey.pem", "ES256")]))
                upload(path, remote / "tokens" / path.name)
            while int(adb("shell", "date", "+%s").strip()) < issued + 3: time.sleep(1)
            for name, presentation, policy, accepted, padded in protocol.plan():
                scenario = manifest["run_id"] + "-" + mode + "-" + name
                print(scenario, flush=True)
                origin["hosts"][args.hostname]["certificates"]["real"]["chain"] = "certificates/" + presentation + "-fullchain.pem"
                origin_path.write_text(json.dumps(origin)); upload(origin_path, remote / "manifest.json")
                ssh("python3", remote / "control.py", "--state", remote / "state.json", "--host", "all",
                    "--mode", "primary" if mode == "primary" else "compat", "--phase", "real", "--fault", "none",
                    "--key-file", key_path.name, "--claim-file", mode + "-" + policy + ".jws", "--generation", scenario)
                ssh("systemctl", "restart", unit)
                issuer_provider = "zerossl" if "zerossl" in presentation else "le"
                issuer = signing.issuer_id(fixture / (issuer_provider + "-issuer.pem"))
                output = args.run_dir / (mode + "-" + name + ".csv")
                private = "/data/user/0/" + PACKAGE + "/files/" + scenario + ".csv"
                command = ["shell", "am", "start", "-S", "-W", "-n", PACKAGE + "/.MainActivity",
                    "--es", "benchmark_type", "crosssign", "--es", "target_hostname", args.hostname,
                    "--es", "scenario", scenario, "--es", "expected_issuer_id", issuer,
                    "--es", "output_csv", private, "--ei", "iterations", str(args.iterations),
                    "--ez", "expect_success", str(accepted).lower()]
                if padded: command += ["--es", "expected_extra_id", signing.issuer_id(fixture / "le-issuer.pem")]
                adb("logcat", "-c"); adb(*command)
                deadline = time.monotonic() + 180
                while True:
                    raw = adb("exec-out", "run-as", PACKAGE, "cat", private, check=False)
                    if raw.startswith("Scenario,"): output.write_text(raw); break
                    errors = adb("logcat", "-d", "-s", "MainActivity:E", "*:S")
                    if "Cross-sign test failed" in errors: raise RuntimeError(errors[-3000:])
                    if time.monotonic() > deadline: raise TimeoutError("Missing public-cross observation: " + errors[-2000:])
                    time.sleep(0.5)
                with output.open(newline="") as stream: rows = list(csv.DictReader(stream))
                if len(rows) != args.iterations or any(row["Result"] != "PASS" for row in rows):
                    raise ValueError("Public cross-CA case failed; raw observations retained: " + output.name)
                audit_deadline = time.monotonic() + 5
                while True:
                    events = []
                    for line in ssh("journalctl", "-u", unit, "--since", since, "-o", "cat", "--no-pager").splitlines():
                        try: events.append(json.loads(line))
                        except ValueError: continue
                    try:
                        audit = audit_public_requests(events, scenario, args.iterations, accepted)
                        break
                    except ValueError:
                        if time.monotonic() > audit_deadline:
                            output.with_suffix(".audit-failed.json").write_text(json.dumps(events, indent=2) + "\n")
                            raise
                        time.sleep(0.5)
                output.with_suffix(".audit.json").write_text(json.dumps(audit, indent=2) + "\n")
                manifest["cells"].append({"mode": mode, "case": name, "scenario": scenario,
                    "presentation": presentation, "policy": policy, "accepted": accepted, "file": output.name})
                save()
        # Leave the newly requested endpoint in a usable dual-issuer state,
        # without rolling its protected highest-seen floors back to earlier tests.
        final_dir = args.run_dir / "final-policies"
        final_dir.mkdir()
        issued = max(int(time.time()), int(adb("shell", "date", "+%s").strip())) + 1
        for root_mode, prefix in (("primary", "my-app"), ("compat", "my-dcp")):
            path = final_dir / ("ClaimSigningKey." + root_mode + ".jws")
            payload = {"cnf": {"jwk": json.loads((source / "my-claim-pubkey.jwk").read_text())}, "iat": issued, "exp": issued + 3600}
            path.write_text(signing.general_jws(payload, [(source / (prefix + "-key.pem"), source / (prefix + "-pubkey.pem"), "ES256")]))
            upload(path, remote / "tokens" / path.name)
        final_claim = final_dir / "ServerCertClaim.jws"
        final_claim.write_text(signing.general_jws({"subject": subject, "san": sans,
            "issuer": certificate_info["issuer_sets"]["dual"], "iat": issued, "exp": issued + 3600},
            [(source / "my-claim-key.pem", source / "my-claim-pubkey.pem", "ES256")]))
        upload(final_claim, remote / "tokens" / final_claim.name)
        origin["hosts"][args.hostname]["certificates"]["real"]["chain"] = "certificates/le-fullchain.pem"
        origin_path.write_text(json.dumps(origin)); upload(origin_path, remote / "manifest.json")
        ssh("python3", remote / "control.py", "--state", remote / "state.json", "--host", "all",
            "--mode", "primary", "--phase", "real", "--fault", "none",
            "--key-file", "ClaimSigningKey.primary.jws", "--claim-file", "ServerCertClaim.jws", "--generation", "idle-dual")
        ssh("systemctl", "restart", unit)
        ssh("python3", "-c", ready_code)
        manifest["endpoint_finalized"] = True
        successful = True
        manifest["state"] = "complete"
    except BaseException as error:
        manifest.update(state="failed", error=str(error))
        raise
    finally:
        if installed:
            try:
                adb("install", "-r", restore_apk)
                manifest["restored_app"] = True
            except Exception as error: manifest.update(state="failed", cleanup_error=str(error))
        if routed and not successful:
            upload(args.run_dir / "haproxy-before.cfg", old_remote / "haproxy.cfg")
            ssh("systemctl", "kill", "--kill-whom=main", "--signal=USR2", front_unit)
            ssh("systemctl", "stop", unit)
        if old_power == "null": adb("shell", "settings", "delete", "global", "stay_on_while_plugged_in")
        else: adb("shell", "settings", "put", "global", "stay_on_while_plugged_in", old_power)
        save()
    print("Completed public-root-only experiment; run summarize-public-cross-results.py", flush=True)


if __name__ == "__main__": main()
