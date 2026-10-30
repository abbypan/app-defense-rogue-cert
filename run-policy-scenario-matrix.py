#!/usr/bin/env python3
"""Device experiments for fail-closed availability and explicit cross-app TLS.

Run through run-policy-scenario-benchmark.sh, never as an unconfigured test.
No device operations occur at import. No AOSP build, flash, reboot, or rollback.
"""
from __future__ import annotations

import argparse
import csv
import importlib.util
import json
from pathlib import Path
import signal
import time

from benchmark_rtt_network import IsolatedRttLink

ROOT = Path(__file__).resolve().parent
TARGET, CALLER, HIDDEN = "com.cert.aspin", "com.cert.aspin.caller", "com.cert.aspin.hidden"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def case_specs():
    def case(name, caller=CALLER, api="cross", operation="protected", expected="accepted",
             error="none", force=False, cache="any"):
        return dict(name=name, Caller=caller, API=api, Target=TARGET if api == "cross" else "",
                    Operation=operation, Expected_Outcome=expected, error=error,
                    force=force, cache=cache)
    cross = [
        case("cross-prime", TARGET, "self", force=True, cache="two-token-refresh"),
        case("cross-target-hot", cache="hot"),
        case("cross-owner-hot", TARGET, "self", cache="hot"),
        case("cross-rogue-native", operation="native"),
        case("cross-rogue-protected", expected="policy_rejected", cache="hot"),
        case("cross-caller-self", api="self", expected="lookup_refused", error="root-mismatch", force=True),
        case("cross-substituted-root", expected="lookup_refused", error="root-mismatch", force=True),
        case("cross-restored-root", force=True, cache="two-token-refresh"),
        case("cross-invisible", HIDDEN, expected="lookup_refused", error="target-unavailable"),
        case("cross-uninstalled", expected="lookup_refused", error="target-unavailable"),
        case("cross-reinstalled", force=True, cache="two-token-refresh"),
    ]
    available = [
        case("prime", TARGET, "self", force=True, cache="two-token-refresh"),
        case("warm-cross", cache="hot"),
        case("blocked-native-self", TARGET, "self", "native"),
        case("blocked-native-cross", operation="native"),
        case("blocked-hot-self", TARGET, "self", cache="hot"),
        case("blocked-hot-cross", cache="hot"),
        case("ordinary-expired-self", TARGET, "self", expected="lookup_refused", error="debug-egress-denied"),
        case("ordinary-expired-cross", expected="lookup_refused", error="debug-egress-denied"),
        # Normal cache hits need no exemption. Once a fetch is necessary, the
        # existing OS restricts loopback to the debug force-refresh API. Never
        # weaken that service rule or call its egress rejection a network test.
        case("expired-self", TARGET, "self", expected="lookup_refused", error="metadata-503", force=True),
        case("expired-cross", expected="lookup_refused", error="metadata-503", force=True),
        case("expired-native-self", TARGET, "self", "native"),
        case("expired-native-cross", operation="native"),
        case("replay-self", TARGET, "self", expected="lookup_refused", error="expired-replay", force=True),
        case("replay-cross", expected="lookup_refused", error="expired-replay", force=True),
        case("timeout-self", TARGET, "self", expected="lookup_refused", error="metadata-timeout", force=True),
        case("timeout-cross", expected="lookup_refused", error="metadata-timeout", force=True),
        case("restored-self", TARGET, "self", force=True, cache="two-token-refresh"),
        case("restored-cross", cache="hot"),
    ]
    return cross, available


def plan(repeats):
    if repeats < 1:
        raise ValueError("Positive repeats required")
    cross, available = case_specs()
    cells = []
    for mode in ("primary", "compatible"):
        for repeat in range(1, repeats + 1):
            for group, cases in (("cross", cross), ("tk-bound", available), ("tc-bound", available)):
                for case in cases:
                    label = f"{mode}-r{repeat}-{group}-{case['name']}"
                    cells.append(dict(case, Mode=mode, Repeat=repeat, Group=group,
                                      Scenario=label, file=f"{label}.csv"))
    return cells


def validate_row(row, cell):
    for field in ("Scenario", "Caller", "API", "Target", "Operation", "Expected_Outcome"):
        if row.get(field) != cell[field]:
            raise ValueError(f"{cell['Scenario']}: incorrect {field}")
    if row.get("Outcome") != cell["Expected_Outcome"] or row.get("Result") != "PASS":
        raise ValueError(f"{cell['Scenario']}: unexpected result: {row}")
    if row.get("Force_Refresh") != str(cell["force"]).lower():
        raise ValueError("Wrong refresh mode")
    accepted = cell["Expected_Outcome"] == "accepted"
    tls = cell["Expected_Outcome"] != "lookup_refused"
    lookup = cell["Operation"] == "protected" and tls
    for field, expected in (("TLS_Attempted", tls), ("App_Request_Sent", accepted),
                            ("Lookup_Succeeded", lookup)):
        if row.get(field) != str(expected).lower():
            raise ValueError(f"Incorrect {field}: expected {expected}")
    import math
    for field in ("Tk_ms", "Tc_ms", "Policy_ms", "Outcome_ms", "Lookup_Start_ms", "Issued_ms", "Expires_ms"):
        value = float(row[field])
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"Invalid metric {field}")
    if lookup:
        if cell["cache"] != "any" and row["Cache"] != cell["cache"]:
            raise ValueError("Policy cache regime not demonstrated")
        if row["Cache"] == "hot" and (float(row["Tk_ms"]) != 0 or float(row["Tc_ms"]) != 0):
            raise ValueError("Hot observation downloaded a token")
        if row["Cache"] == "two-token-refresh" and (float(row["Tk_ms"]) <= 0 or float(row["Tc_ms"]) <= 0):
            raise ValueError("Missing full refresh evidence")
        if int(row["Expires_ms"]) <= int(row["Lookup_Start_ms"]):
            raise ValueError("Accepted an already expired claim")
    if cell.get("not_before_ms", 0) > int(row["Lookup_Start_ms"]):
        raise ValueError("Claim-expiry boundary not reached on device")


def summarize(directory):
    manifest = json.loads((directory / "matrix.json").read_text())
    cells = manifest["cells"]
    if not cells or len({cell["file"] for cell in cells}) != len(cells):
        raise ValueError("Invalid planned cells")
    if {cell["file"] for cell in cells} != {p.name for p in directory.glob("*.csv") if p.name != "table_policy_scenarios.csv"}:
        raise ValueError("Missing or unexpected scenario evidence")
    rows = []
    for cell in cells:
        with (directory / cell["file"]).open(newline="") as source:
            raw = list(csv.DictReader(source))
        if len(raw) != 1:
            raise ValueError("Expected exactly one raw observation per scenario")
        row = raw[0]
        validate_row(row, cell)
        expected_requests = 1 if row["Outcome"] == "accepted" else 0
        audit = json.loads((directory / f"{cell['Scenario']}.audit.json").read_text())
        if audit != {"Scenario": cell["Scenario"], "Observed_App_Requests": expected_requests}:
            raise ValueError("Server-side request evidence disagrees with app observation")
        rows.append({key: str(value) for key, value in (dict(Mode=cell["Mode"], Repeat=cell["Repeat"], Group=cell["Group"]) | row).items()})
    output = directory / "table_policy_scenarios.csv"
    with output.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)
    return output


class Fixtures:
    def __init__(self):
        self.signing = load("policy_signing", "generate-lifecycle-artifacts.py")
        self.last = max(self.signing.decode_payload(ROOT / "signing/es256" / name)["iat"]
                        for name in ("ClaimSigningKey.primary.jws", "ClaimSigningKey.compat.jws", "ServerCertClaim.jws"))

    def pair(self, mode, short_seconds=None, bound=None):
        signing = ROOT / "signing/es256"
        tk = self.signing.decode_payload(signing / ("ClaimSigningKey.primary.jws" if mode == "primary" else "ClaimSigningKey.compat.jws"))
        tc = self.signing.decode_payload(signing / "ServerCertClaim.jws")
        issued = max(int(time.time()), self.last + 1)
        self.last = issued
        tk.update(iat=issued, exp=issued + (short_seconds if bound == "tk-bound" else 3600))
        tc.update(iat=issued, exp=issued + (short_seconds if bound == "tc-bound" else 3600))
        prefix = "my-app" if mode == "primary" else "my-dcp"
        signers = [(signing / f"{prefix}-key.pem", signing / f"{prefix}-pubkey.pem", "ES256")]
        delegated = [(signing / "my-claim-key.pem", signing / "my-claim-pubkey.pem", "ES256")]
        # Account for the <=2s host/device synchronization tolerance, without
        # moving either clock backwards or bypassing the OS freshness checks.
        while time.time() < issued + 2:
            time.sleep(0.1)
        return (self.signing.general_jws(tk, signers), self.signing.general_jws(tc, delegated),
                min(tk["exp"], tc["exp"]) * 1000)

    def caller_substitution(self, tk):
        import base64
        value = json.loads(tk)["payload"]
        payload = json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))
        signer = ROOT / "signing/es384"
        return self.signing.general_jws(payload, [(signer / "my-app-key.pem", signer / "my-app-pubkey.pem", "ES384")])


class Experiment:
    def __init__(self, device, link, directory, cells, timeout):
        self.device, self.link, self.directory, self.timeout = device, link, directory, timeout
        self.cells = {cell["Scenario"]: cell for cell in cells}

    def observe(self, mode, repeat, group, name, not_before=0):
        label = f"{mode}-r{repeat}-{group}-{name}"
        cell = self.cells[label]
        cell["not_before_ms"] = not_before
        package = cell["Caller"]
        remote = f"/data/user/0/{package}/files/{cell['file']}"
        self.device.adb("shell", "logcat", "-c")
        self.device.adb("shell", "su", "0", "rm", "-f", remote)
        args = ["shell", "am", "start", "-S", "-W", "-n", f"{package}/com.cert.aspin.MainActivity",
                "--es", "benchmark_type", "policyscenario", "--es", "output_csv", remote]
        for key, value in {"scenario": label, "operation": cell["Operation"], "api": cell["API"],
                           "target_package": cell["Target"], "expected_outcome": cell["Expected_Outcome"],
                           "expected_error_kind": cell["error"], "required_cache": cell["cache"]}.items():
            if key == "target_package" and not value: continue
            args.extend(["--es", key, value])
        args.extend(["--ez", "force_refresh", str(cell["force"]).lower(), "--el", "not_before_ms", str(not_before)])
        print(label, flush=True)
        self.device.adb(*args)
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if "ready" in self.device.adb("shell", "su", "0", "sh", "-c", f"'test -f {remote} && echo ready'", check=False):
                destination = self.directory / cell["file"]
                self.device.adb("pull", remote, destination)
                with destination.open(newline="") as stream:
                    rows = list(csv.DictReader(stream))
                if len(rows) != 1:
                    raise RuntimeError("Incomplete raw observation")
                validate_row(rows[0], cell)
                count = self.link.observation_count(label)
                (self.directory / f"{label}.audit.json").write_text(json.dumps(
                    {"Scenario": label, "Observed_App_Requests": count}) + "\n")
                if count != (1 if rows[0]["Outcome"] == "accepted" else 0):
                    raise RuntimeError("Unexpected server-side application request")
                return rows[0]
            logs = self.device.adb("logcat", "-d", "-s", "MainActivity:E", "*:S")
            if "Policy scenario benchmark failed" in logs:
                raise RuntimeError(logs[-3000:])
            time.sleep(0.25)
        raise TimeoutError(label)


def main():
    def interrupted(*_):
        raise KeyboardInterrupt("Cleaning up isolated scenario services")
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device")
    parser.add_argument("--cert-dir", type=Path)
    parser.add_argument("--apk-dir", type=Path)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--short-seconds", type=int, default=60)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--summary-only", action="store_true")
    args = parser.parse_args()
    if args.summary_only:
        print(summarize(args.run_dir)); return
    if not args.device or not args.cert_dir or not args.apk_dir:
        parser.error("--device, --cert-dir and --apk-dir are required for a device run")
    if args.short_seconds < 30 or args.timeout < 30:
        parser.error("Short lifetime and host timeout must be >=30s")
    cells = plan(args.repeats)
    directory = args.run_dir.resolve(); directory.mkdir(parents=True, exist_ok=True)
    if (directory / "matrix.json").exists():
        raise RuntimeError("Refusing to overwrite an existing scenario run")
    manifest = dict(state="planned", cells=cells, repeats=args.repeats, short_seconds=args.short_seconds,
                    definitions={"suppression": "metadata-only 503 or withheld HTTP response; business TLS remains reachable",
                                 "expiry": "real-time wait to min(exp_k, exp_c); no state clearing or clock rollback",
                                 "audit": "tagged HTTP application requests, not a packet-level leakage measurement",
                                 "unusable_cache": "expired primed pair, not an erased-state cold boot",
                                 "debug_transport": "ordinary expired lookups hit the OS special-use egress guard; actual metadata fault/replay probes use debug forced refresh AFTER signed expiry",
                                 "timing": "single observation per case/repeat; no latency-distribution claim"})
    manifest_path = directory / "matrix.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    device = load("policy_rtt_device", "run-rtt-cache-matrix.py").Device(args.device)
    fixtures = Fixtures()
    project = ROOT / "ASPin/es256/app/build/outputs/apk"
    with IsolatedRttLink(args.cert_dir, directory / "network") as link:
        previous = [line.split()[1:] for line in device.adb("reverse", "--list").splitlines()
                    if len(line.split()) == 3 and line.split()[1] in {"tcp:80", "tcp:443", "tcp:19090"}]
        try:
            for source, destination in link.host_ports.items():
                device.adb("reverse", f"tcp:{source}", f"tcp:{destination}")
            for package, build in ((CALLER, "crossAppCaller"), (HIDDEN, "crossAppHidden")):
                device.adb("uninstall", package, check=False)
                device.adb("install", "-r", project / build / f"app-{build}.apk")
            experiment = Experiment(device, link, directory, cells, args.timeout)
            for mode in ("primary", "compatible"):
                for repeat in range(1, args.repeats + 1):
                    device.adb("uninstall", TARGET, check=False)
                    target_apk = (args.apk_dir / "ASPin-es256.apk" if mode == "primary"
                                  else project / "compatibilityBenchmark/app-compatibilityBenchmark.apk")
                    device.adb("install", "-r", target_apk)
                    link.set_profile("real"); link.set_policy_transport("serve")
                    tk, tc, _ = fixtures.pair(mode); link.publish_pair("es256", tk, tc)
                    observe = lambda name, group="cross", boundary=0: experiment.observe(mode, repeat, group, name, boundary)
                    for name in ("cross-prime", "cross-target-hot", "cross-owner-hot"):
                        observe(name)
                    link.set_profile("rogue")
                    observe("cross-rogue-native"); observe("cross-rogue-protected")
                    link.set_profile("real")
                    observe("cross-caller-self")
                    link.publish_pair("es256", fixtures.caller_substitution(tk), tc)
                    observe("cross-substituted-root")
                    link.publish_pair("es256", tk, tc); observe("cross-restored-root")
                    observe("cross-invisible")
                    device.adb("uninstall", TARGET); observe("cross-uninstalled")
                    device.adb("install", "-r", target_apk); observe("cross-reinstalled")
                    for group in ("tk-bound", "tc-bound"):
                        tk, tc, boundary = fixtures.pair(mode, args.short_seconds, group)
                        link.publish_pair("es256", tk, tc)
                        prime = observe("prime", group)
                        if int(prime["Expires_ms"]) != boundary:
                            raise RuntimeError("OS did not return min(exp_k,exp_c)")
                        observe("warm-cross", group)
                        link.set_policy_transport("503")
                        for name in ("blocked-native-self", "blocked-native-cross", "blocked-hot-self", "blocked-hot-cross"):
                            observe(name, group)
                        print(f"Waiting for real signed expiry: {group}", flush=True)
                        while time.time() * 1000 < boundary + 1500:
                            time.sleep(max(0, min(1, (boundary + 1500 - time.time() * 1000) / 1000)))
                        for name in ("ordinary-expired-self", "ordinary-expired-cross", "expired-self", "expired-cross", "expired-native-self", "expired-native-cross"):
                            observe(name, group, boundary)
                        link.set_policy_transport("serve")
                        observe("replay-self", group, boundary); observe("replay-cross", group, boundary)
                        link.set_policy_transport("timeout")
                        observe("timeout-self", group, boundary); observe("timeout-cross", group, boundary)
                        link.set_policy_transport("serve")
                        new_tk, new_tc, _ = fixtures.pair(mode)
                        link.publish_pair("es256", new_tk, new_tc)
                        observe("restored-self", group); observe("restored-cross", group)
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
            print(summarize(directory))
            manifest["state"] = "complete"
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        finally:
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
            for port in link.host_ports:
                device.adb("reverse", "--remove", f"tcp:{port}", check=False)
            for source, destination in previous:
                device.adb("reverse", source, destination)
            for package in (CALLER, HIDDEN):
                device.adb("uninstall", package, check=False)


if __name__ == "__main__":
    main()
