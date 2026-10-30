#!/usr/bin/env python3
"""Audited public-CA, direct-Internet cross-app and fail-closed device cases.

Run after the four-scheme comparison. Uses the existing isolated hk origin;
never flashes, resets protected state, changes DNS, or sends authority keys.
"""
import argparse
import atexit
import csv
from datetime import datetime, timezone
import fcntl
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import sys
import time
import uuid
from benchmark_device_network import wait_for_internet

ROOT = Path(__file__).resolve().parent
TARGET, CALLER, HIDDEN = "com.cert.aspin", "com.cert.aspin.caller", "com.cert.aspin.hidden"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(command, check=True):
    return subprocess.run(list(map(str, command)), check=check, capture_output=True, text=True).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", default="3A201FDJH000GP")
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--apk-dir", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--short-seconds", type=int, default=60)
    parser.add_argument("--after-matrix", type=Path,
                        help="Wait for this matrix.json to complete, and refuse to run if it failed")
    args = parser.parse_args()
    if args.after_matrix:
        deadline = time.monotonic() + 3600
        while True:
            previous = json.loads(args.after_matrix.read_text())
            if previous["state"] == "complete": break
            if previous["state"] == "failed": raise RuntimeError("Preceding comparison failed")
            if time.monotonic() > deadline: raise TimeoutError("Preceding comparison")
            time.sleep(5)
    if args.short_seconds < 45: parser.error("At least 45 seconds required")
    if args.run_dir.exists(): raise ValueError("Use a new result directory")
    args.run_dir.mkdir(parents=True)
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
    original_stayon = adb("shell", "settings", "get", "global", "stay_on_while_plugged_in").strip()
    def restore_power():
        if original_stayon == "null": adb("shell", "settings", "delete", "global", "stay_on_while_plugged_in", check=False)
        else: adb("shell", "settings", "put", "global", "stay_on_while_plugged_in", original_stayon, check=False)
    atexit.register(restore_power)
    adb("shell", "svc", "power", "stayon", "true")
    adb("shell", "input", "keyevent", "KEYCODE_WAKEUP")
    adb("shell", "wm", "dismiss-keyguard")
    wait_for_internet(adb, "es256.idouzi.top")
    manifest = {"state": "running", "run_id": "p" + uuid.uuid4().hex[:12],
                "created_utc": datetime.now(timezone.utc).isoformat(), "cases": [],
                "transport": "Pixel 8 Internet -> public-CA hk:443; no adb reverse",
                "scope": "single observed functional runs, not latency distributions",
                "short_seconds": args.short_seconds,
                "server_since": ssh("date", "-u", "--date=1 minute ago", "+%Y-%m-%dT%H:%M:%SZ").strip()}
    def save():
        (args.run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    save()
    matrix = load("remote_policy_matrix", "run-policy-scenario-matrix.py")
    fixtures = matrix.Fixtures()
    signing = load("remote_policy_signing", "generate-lifecycle-artifacts.py")
    observations = []
    token_dir = remote / "tokens/es256"
    def publish(mode, group, bound=None):
        tk, tc, expiry = fixtures.pair(mode, args.short_seconds, bound)
        prefix = "my-app" if mode == "primary" else "my-dcp"
        signers = [(ROOT / "signing" / variant / (prefix + "-key.pem"),
                    ROOT / "signing" / variant / (prefix + "-pubkey.pem"), alg)
                   for variant, alg in (("es384", "ES384"), ("rsa3072", "PS256"),
                                        ("rsa4096", "PS384"), ("es256", "ES256"))]
        payload = json.loads(__import__("base64").urlsafe_b64decode(
            json.loads(tk)["payload"] + "=" * (-len(json.loads(tk)["payload"]) % 4)))
        content = {"tk": tk, "tc": tc, "shared": signing.general_jws(payload, signers),
                   "substituted": fixtures.caller_substitution(tk)}
        names = {}
        for kind, value in content.items():
            path = args.run_dir / f"{mode}-{group}-{kind}.jws"
            path.write_text(value)
            run(["scp", "-q", path, f"{alias}:{token_dir}/{path.name}"])
            names[kind] = path.name
        # Host and phone need not share an exact wall clock. Observe the phone
        # reaching signed iat rather than moving its clock or weakening checks.
        while int(adb("shell", "date", "+%s").strip()) < payload["iat"]:
            time.sleep(1)
        return names, expiry
    def control(mode, label, files, phase="real", fault="none", key="tk"):
        ssh("python3", remote / "control.py", "--state", remote / "state.json", "--host", "all",
            "--mode", mode, "--phase", phase, "--fault", fault, "--key-file", files[key],
            "--claim-file", files["tc"], "--generation", label)
    def observe(mode, group, name, files, *, caller=CALLER, api="cross", operation="protected",
                expected="accepted", error="none", force=False, cache="any", phase="real", fault="none", key="tk"):
        label = manifest["run_id"] + "-" + mode + "-" + group + "-" + name
        control(mode, label, files, phase, fault, key)
        path = args.run_dir / (label + ".csv")
        private = "/data/user/0/" + caller + "/files/" + path.name
        command = ["shell", "am", "start", "-S", "-W", "-n", caller + "/com.cert.aspin.MainActivity",
                   "--es", "benchmark_type", "policyscenario", "--es", "output_csv", private]
        for key_, value in {"scenario": label, "operation": operation, "api": api,
                            "target_package": TARGET if api == "cross" else "", "expected_outcome": expected,
                            "expected_error_kind": error, "required_cache": cache}.items():
            if key_ == "target_package" and api == "self": continue
            command.extend(["--es", key_, value])
        command.extend(["--ez", "force_refresh", str(force).lower()])
        print(label, flush=True)
        adb("logcat", "-c"); adb(*command)
        deadline = time.monotonic() + 90
        while True:
            data = adb("exec-out", "run-as", caller, "cat", "files/" + path.name, check=False)
            if data.startswith("Scenario,"): path.write_text(data); break
            errors = adb("logcat", "-d", "-s", "MainActivity:E", "*:S")
            if "Policy scenario benchmark failed" in errors: raise RuntimeError(errors[-3000:])
            if time.monotonic() >= deadline:
                raise TimeoutError(adb("logcat", "-d", "-s", "MainActivity:E", "*:S")[-2000:])
            time.sleep(0.5)
        with path.open() as stream: rows = list(csv.DictReader(stream))
        if len(rows) != 1: raise ValueError("Expected one observation")
        cell = {"Scenario": label, "Caller": caller, "API": api, "Target": TARGET,
                "Operation": operation, "Expected_Outcome": expected, "force": force,
                "cache": cache, "error": error}
        # Self API leaves the CSV target empty, unlike explicit cross lookup.
        if api == "self": cell["Target"] = ""
        matrix.validate_row(rows[0], cell)
        events = []
        deadline = time.monotonic() + 10
        while True:
            events = []
            for line in ssh("journalctl", "-u", unit, "--since", manifest["server_since"],
                            "-o", "cat", "--no-pager").splitlines():
                try: event = json.loads(line)
                except ValueError: continue
                if event.get("generation") == label and event.get("observation") == label and event.get("path") == "/":
                    events.append(event)
            wanted = 1 if expected == "accepted" else 0
            if len(events) == wanted or time.monotonic() >= deadline: break
            time.sleep(0.5)
        if len(events) != wanted or any(item.get("status") != 200 for item in events):
            raise ValueError("Application-request audit mismatch")
        path.with_suffix(".audit.json").write_text(json.dumps({"business_requests": len(events), "expected": wanted}) + "\n")
        observations.append(rows[0] | {"Mode": mode, "Group": group})
        manifest["cases"].append({"scenario": label, "outcome": rows[0]["Outcome"], "result": "PASS"})
        save()
    def reboot():
        adb("reboot"); adb("wait-for-device")
        deadline = time.monotonic() + 240
        while adb("shell", "getprop", "sys.boot_completed").strip() != "1":
            if time.monotonic() > deadline: raise TimeoutError("Device reboot")
            time.sleep(2)
        adb("root"); adb("wait-for-device")
        adb("shell", "input", "keyevent", "KEYCODE_WAKEUP")
        adb("shell", "wm", "dismiss-keyguard")
        wait_for_internet(adb, "es256.idouzi.top")
    def wait_for_device_expiry(expiry, staged_at=None):
        while (int(adb("shell", "date", "+%s").strip()) * 1000 <= expiry + 1000
               or (staged_at is not None and time.monotonic() - staged_at < args.short_seconds)):
            time.sleep(1)
    def with_issuers(mode, files, issuers):
        tc_path = args.run_dir / files["tc"]
        payload = signing.decode_payload(tc_path)
        payload["issuer"] = issuers
        signing_dir = ROOT / "signing/es256"
        tc_path.write_text(signing.general_jws(payload, [(
            signing_dir / "my-claim-key.pem", signing_dir / "my-claim-pubkey.pem", "ES256")]))
        run(["scp", "-q", tc_path, f"{alias}:{token_dir}/{tc_path.name}"])
    def claim_replay_probe(mode, name, files):
        label = manifest["run_id"] + "-" + mode + "-" + name
        control(mode, label, files)
        path = args.run_dir / (label + ".csv")
        private = "/data/user/0/" + TARGET + "/files/" + path.name
        adb("shell", "am", "start", "-S", "-W", "-n", TARGET + "/.MainActivity",
            "--es", "benchmark_type", "claimprobe", "--es", "output_csv", private,
            "--es", "probe_label", label, "--ez", "expect_success", "false", "--ez", "force_refresh", "true",
            "--es", "expected_error", "anti-rollback")
        deadline = time.monotonic() + 60
        while True:
            data = adb("exec-out", "run-as", TARGET, "cat", "files/" + path.name, check=False)
            if data.startswith("Label,"): path.write_text(data); break
            if time.monotonic() > deadline: raise TimeoutError(label)
            time.sleep(0.5)
        with path.open() as stream: rows = list(csv.DictReader(stream))
        if (len(rows) != 1 or rows[0]["Result"] != "PASS" or rows[0]["ObservedSuccess"] != "false"
                or "anti-rollback" not in rows[0]["Error"].lower()):
            raise ValueError("Replay did not produce the required rollback refusal")
        manifest["cases"].append({"scenario": label, "outcome": "rollback_refused", "result": "PASS",
                                  "scope": "claim lookup only; no business connection invoked"})
        save()
    try:
        for mode, suffix in (("primary", ""), ("compat", "-compatible")):
            reboot()  # Clear RAM tokens only; protected H_k/H_c stay intact.
            for package in (TARGET, CALLER, HIDDEN): adb("uninstall", package, check=False)
            target_apk = args.apk_dir / ("ASPin-es256" + suffix + ".apk")
            adb("install", target_apk)
            for build_type in ("crossAppCaller", "crossAppHidden"):
                adb("install", ROOT / "ASPin/es256/app/build/outputs/apk" / build_type / ("app-" + build_type + ".apk"))
            files, _ = publish(mode, "cross")
            def cross(name, **kw): return observe(mode, "cross", name, files, **kw)
            cross("empty-cache-suppressed", caller=TARGET, api="self", expected="lookup_refused",
                  error="metadata-503", fault="503")
            cross("prime", caller=TARGET, api="self", force=True, cache="two-token-refresh")
            cross("target-hot", cache="hot")
            cross("rogue-native", operation="native", phase="rogue")
            cross("rogue-protected", phase="rogue", expected="policy_rejected", cache="hot")
            cross("caller-self", api="self", expected="lookup_refused", error="root-mismatch", force=True)
            cross("caller-root-substitution", key="substituted", expected="lookup_refused", error="root-mismatch", force=True)
            cross("shared-four-signatures", key="shared", force=True, cache="two-token-refresh")
            cross("invisible-target", caller=HIDDEN, expected="lookup_refused", error="target-unavailable")
            adb("uninstall", TARGET)
            cross("uninstalled-target", expected="lookup_refused", error="target-unavailable")
            adb("install", target_apk)
            cross("reinstalled-target", force=True, cache="two-token-refresh")
            if mode == "compat":
                primary_files, _ = publish("primary", "parallel-root")
                observe(mode, "parallel", "app-root-with-manifest", primary_files,
                        caller=TARGET, api="self", force=True, cache="two-token-refresh")
                compatible_files, _ = publish(mode, "parallel-root")
                observe(mode, "parallel", "manifest-root-with-app-root", compatible_files,
                        caller=TARGET, api="self", force=True, cache="two-token-refresh")
                reboot()  # Isolate K_s availability cases from the live K_a cache.
            for bound in ("tk-bound", "tc-bound"):
                files, expiry = publish(mode, bound, bound)
                def case(name, **kw): return observe(mode, bound, name, files, **kw)
                case("prime", caller=TARGET, api="self", force=True, cache="two-token-refresh")
                case("blocked-hot-self", caller=TARGET, api="self", cache="hot", fault="503")
                case("blocked-hot-cross", cache="hot", fault="503")
                case("blocked-native", operation="native", fault="503")
                print(f"Waiting for signed expiration {expiry // 1000} on device clock", flush=True)
                wait_for_device_expiry(expiry)
                case("expired-self", caller=TARGET, api="self", expected="lookup_refused", error="metadata-503", fault="503")
                case("expired-cross", expected="lookup_refused", error="metadata-503", fault="503")
                case("expired-native", operation="native", fault="503")
                case("expired-replay", expected="lookup_refused", error="expired-replay")
                case("metadata-timeout", expected="lookup_refused", error="metadata-timeout", fault="timeout")
                files, _ = publish(mode, bound + "-restored")
                case("restored-self", caller=TARGET, api="self", force=True, cache="two-token-refresh")
                case("restored-cross", cache="hot")
            # Migration uses the actual public CA certificates already deployed:
            # the former rogue profile becomes authorized only in the signed overlap.
            current_issuers = signing.decode_payload(ROOT / "signing/es256/ServerCertClaim.jws")["issuer"]
            issuer_module = load("remote_issuer_policy", "signing/issuer_policy.py")
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            import hashlib
            import base64
            rogue_leaf = x509.load_pem_x509_certificate((ROOT / "rogueserver/etc/cert/es256/rogue-cert.crt").read_bytes())
            chain = x509.load_pem_x509_certificates((ROOT / "rogueserver/etc/cert/es256/rogue-fullchain.pem").read_bytes())
            next_issuers = ["sha256:" + base64.urlsafe_b64encode(hashlib.sha256(
                ca.public_bytes(serialization.Encoding.DER)).digest()).rstrip(b"=").decode()
                for ca in issuer_module.direct_issuer_certificates(rogue_leaf, chain)]
            initial, _ = publish(mode, "migration-current", "tc-bound")
            observe(mode, "migration", "current-only", initial, caller=TARGET, api="self", force=True)
            observe(mode, "migration", "next-before-overlap", initial, caller=TARGET, api="self",
                    phase="rogue", cache="hot", expected="policy_rejected")
            overlap, expiry = publish(mode, "migration-overlap", "tc-bound")
            with_issuers(mode, overlap, sorted(set(current_issuers + next_issuers)))
            observe(mode, "migration", "overlap-current", overlap, caller=TARGET, api="self", force=True)
            staged_at = time.monotonic()  # Already published and observed; wait a full interval from here.
            observe(mode, "migration", "overlap-next-probe", overlap, caller=TARGET, api="self", phase="rogue", cache="hot")
            control(mode, manifest["run_id"] + "-staging-current", overlap, phase="real")
            wait_for_device_expiry(expiry, staged_at)
            manifest.setdefault("migration_staging", []).append({"mode": mode,
                "lmax_seconds": args.short_seconds, "elapsed_seconds": time.monotonic() - staged_at,
                "overlap_exp_ms": expiry})
            save()
            final, _ = publish(mode, "migration-next", "tc-bound")
            with_issuers(mode, final, next_issuers)
            observe(mode, "migration", "joint-cutover-next", final, caller=TARGET, api="self", force=True, phase="rogue")
            observe(mode, "migration", "retired-current-rejected", final, caller=TARGET, api="self", cache="hot",
                    expected="policy_rejected")
            # Concrete delegated-key change, matching and mixed pairs, then replay.
            old_pair, _ = publish(mode, "claim-key-old")
            observe(mode, "claim-key", "old-pair", old_pair, caller=TARGET, api="self", force=True)
            new_pair, _ = publish(mode, "claim-key-new")
            tk_path, tc_path = (args.run_dir / new_pair[name] for name in ("tk", "tc"))
            tk_payload, tc_payload = signing.decode_payload(tk_path), signing.decode_payload(tc_path)
            new_claim_dir = ROOT / "signing/es384"
            tk_payload["cnf"]["jwk"] = json.loads((new_claim_dir / "my-claim-pubkey.jwk").read_text())
            root_dir = ROOT / "signing/es256"
            stem = "my-app" if mode == "primary" else "my-dcp"
            tk_path.write_text(signing.general_jws(tk_payload, [(root_dir / (stem + "-key.pem"),
                root_dir / (stem + "-pubkey.pem"), "ES256")]))
            tc_path.write_text(signing.general_jws(tc_payload, [(new_claim_dir / "my-claim-key.pem",
                new_claim_dir / "my-claim-pubkey.pem", "ES384")]))
            run(["scp", "-q", tk_path, tc_path, f"{alias}:{token_dir}/"])
            observe(mode, "claim-key", "old-tk-new-tc", old_pair | {"tc": new_pair["tc"]},
                    caller=TARGET, api="self", force=True, expected="lookup_refused", error="root-mismatch")
            observe(mode, "claim-key", "new-tk-old-tc", new_pair | {"tc": old_pair["tc"]},
                    caller=TARGET, api="self", force=True, expected="lookup_refused", error="root-mismatch")
            observe(mode, "claim-key", "matching-new", new_pair, caller=TARGET, api="self", force=True)
            claim_replay_probe(mode, "claim-key-old-replay", old_pair)
            if mode == "primary":
                old_app_pair, _ = publish(mode, "app-root-old")
                observe(mode, "app-root", "old-installed-root", old_app_pair, caller=TARGET, api="self", force=True)
                apksigner = "/opt/android-sdk/build-tools/35.0.0/apksigner"
                lineage = args.run_dir / "app-signing-lineage.bin"
                rotated_apk = args.run_dir / "ASPin-es256-app-root-rotated.apk"
                old_dir, next_dir = ROOT / "signing/es256", ROOT / "signing/es384"
                run([apksigner, "rotate", "--out", lineage, "--old-signer", "--ks", old_dir / "my-app-key.keystore",
                     "--ks-key-alias", "my_app", "--ks-pass", "pass:123456", "--key-pass", "pass:123456",
                     "--set-installed-data", "true", "--new-signer", "--ks", next_dir / "my-app-key.keystore",
                     "--ks-key-alias", "my_app", "--ks-pass", "pass:123456", "--key-pass", "pass:123456"])
                run([apksigner, "sign", "--out", rotated_apk, "--ks", next_dir / "my-app-key.keystore",
                     "--ks-key-alias", "my_app", "--ks-pass", "pass:123456", "--key-pass", "pass:123456",
                     "--v1-signing-enabled", "false", "--v2-signing-enabled", "false", "--lineage", lineage,
                     "--rotation-min-sdk-version", "28", target_apk])
                transitional, _ = publish(mode, "app-root-transitional")
                path = args.run_dir / transitional["tk"]
                payload = signing.decode_payload(path)
                path.write_text(signing.general_jws(payload, [
                    (old_dir / "my-dcp-key.pem", old_dir / "my-dcp-pubkey.pem", "ES256"),
                    (next_dir / "my-dcp-key.pem", next_dir / "my-dcp-pubkey.pem", "ES384"),
                    (old_dir / "my-app-key.pem", old_dir / "my-app-pubkey.pem", "ES256"),
                    (next_dir / "my-app-key.pem", next_dir / "my-app-pubkey.pem", "ES384")]))
                run(["scp", "-q", path, f"{alias}:{token_dir}/{path.name}"])
                adb("install", "-r", rotated_apk)  # Android must authenticate the signing lineage.
                observe(mode, "app-root", "lineage-transition-signatures-three-four", transitional,
                        caller=TARGET, api="self", force=True)
                new_app_pair, _ = publish(mode, "app-root-new-only")
                path = args.run_dir / new_app_pair["tk"]
                path.write_text(signing.general_jws(signing.decode_payload(path), [(
                    next_dir / "my-app-key.pem", next_dir / "my-app-pubkey.pem", "ES384")]))
                run(["scp", "-q", path, f"{alias}:{token_dir}/{path.name}"])
                observe(mode, "app-root", "new-only", new_app_pair, caller=TARGET, api="self", force=True)
                observe(mode, "app-root", "latest-installed-target-cross-query", new_app_pair, force=True)
                claim_replay_probe(mode, "app-root-transition-replay", transitional)
            else:
                old_ks_pair, _ = publish(mode, "ks-root-old")
                observe(mode, "ks-root", "old-manifest-root", old_ks_pair, caller=TARGET, api="self", force=True)
                rotated_apk = args.apk_dir / "ASPin-es256-compatible-rotated-root.apk"
                if not rotated_apk.is_file(): raise FileNotFoundError("Build the manifest-root rotation APK first")
                adb("install", "-r", rotated_apk)  # Same app signer, authenticated new manifest key.
                next_ks_pair, _ = publish(mode, "ks-root-new")
                tk_path, tc_path = (args.run_dir / next_ks_pair[name] for name in ("tk", "tc"))
                tk_payload, tc_payload = signing.decode_payload(tk_path), signing.decode_payload(tc_path)
                # The new K_s namespace need not inherit the old K_s issuance floor.
                lower_iat = signing.decode_payload(args.run_dir / old_ks_pair["tk"])["iat"] - 10
                for payload in (tk_payload, tc_payload): payload.update(iat=lower_iat, exp=lower_iat + 3600)
                next_dir, claim_dir = ROOT / "signing/es384", ROOT / "signing/es256"
                tk_path.write_text(signing.general_jws(tk_payload, [(
                    next_dir / "my-dcp-key.pem", next_dir / "my-dcp-pubkey.pem", "ES384")]))
                tc_path.write_text(signing.general_jws(tc_payload, [(
                    claim_dir / "my-claim-key.pem", claim_dir / "my-claim-pubkey.pem", "ES256")]))
                run(["scp", "-q", tk_path, tc_path, f"{alias}:{token_dir}/"])
                observe(mode, "ks-root", "authenticated-new-manifest-namespace", next_ks_pair,
                        caller=TARGET, api="self", force=True)
                observe(mode, "ks-root", "old-manifest-root-no-longer-eligible", old_ks_pair,
                        caller=TARGET, api="self", force=True, expected="lookup_refused", error="root-mismatch")
        manifest["state"] = "complete"
        with (args.run_dir / "summary.csv").open("w", newline="") as stream:
            writer = csv.DictWriter(stream, observations[0].keys())
            writer.writeheader(); writer.writerows(observations)
    except BaseException as error:
        manifest["state"] = "failed"; manifest["error"] = str(error)
        raise
    finally:
        restore_power()
        atexit.unregister(restore_power)
        ssh("python3", remote / "control.py", "--state", remote / "state.json", "--host", "all",
            "--mode", "primary", "--phase", "real", "--fault", "none",
            "--key-file", "ClaimSigningKey.primary.jws", "--claim-file", "ServerCertClaim.jws", "--generation", "scenario-idle")
        # Do not leave old standard endpoint artifacts below newly accepted floors.
        run([sys.executable, ROOT / "gen-trust-artifacts.py"])
        run([sys.executable, ROOT / "update-remote-policies.py", "--deployment", args.deployment])
        manifest["standard_policies_refreshed"] = True
        save()


if __name__ == "__main__":
    main()
