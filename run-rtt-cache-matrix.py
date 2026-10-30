#!/usr/bin/env python3
"""Run only after the robustness harness creates current debug CAs and APKs.

No AOSP build, flash, kernel reboot, or clock rollback occurs here. The Android
framework restarts outside timing to isolate compatible-mode volatile caches.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import random
import signal
import subprocess
import sys
import time

from benchmark_rtt_network import ALGORITHMS, IsolatedRttLink


ROOT = Path(__file__).resolve().parent
PACKAGE = "com.cert.aspin"
MODES = (("primary", "TLS", "none"), ("primary", "ASPin", "hot"),
         ("primary", "ASPin", "cold-forced-refresh"), ("scp", "SCP", "static"),
         ("dcp", "DCP", "hot"), ("dcp", "DCP", "cold-forced-refresh"))
MODES += (("compatible", "ASPin-compatible", "hot"),
          ("compatible", "ASPin-compatible", "cold-forced-refresh"))
spec = importlib.util.spec_from_file_location("rtt_summary", ROOT / "summarize-rtt-cache-results.py")
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)


def plan(rt_values: list[int], repeats: int, seed: int) -> list[dict]:
    if not rt_values or len(set(rt_values)) != len(rt_values) or any(not 0 <= value <= 2000 for value in rt_values):
        raise ValueError("RTT values must be distinct integers in [0, 2000] ms")
    if repeats < 1:
        raise ValueError("Repeats must be positive")
    randomizer = random.Random(seed)
    blocks = [(repeat, rtt, algorithm, phase)
              for repeat in range(1, repeats + 1) for rtt in rt_values
              for algorithm in ALGORITHMS for phase in ("real", "rogue")]
    randomizer.shuffle(blocks)
    cells = []
    for repeat, rtt, algorithm, phase in blocks:
        # A same-RTT/phase native baseline is always first. Randomize the five
        # protected cases, rather than confounding every RTT with one fixed order.
        protected = list(MODES[1:])
        randomizer.shuffle(protected)
        for mode, scheme, cache in [MODES[0], *protected]:
            cells.append({"Algorithm": algorithm, "Mode": mode, "Scheme": scheme,
                          "Phase": phase, "Cache": cache, "Added_RTT_ms": rtt,
                          "Repeat": repeat,
                          "file": f"rtt-{rtt}-{algorithm}-{phase}-{scheme}-{cache}-r{repeat}.csv"})
    return cells


class Device:
    def __init__(self, serial: str):
        self.serial = serial

    def adb(self, *arguments, check=True):
        result = subprocess.run(["adb", "-s", self.serial, *map(str, arguments)],
                                check=check, text=True, capture_output=True)
        return result.stdout

    def install(self, directory: Path, algorithm: str, mode: str):
        suffix = {"primary": "", "scp": "-scp", "dcp": "-dcp", "compatible": "-compatible"}[mode]
        apk = directory / f"ASPin-{algorithm}{suffix}.apk"
        if not apk.is_file():
            raise RuntimeError(f"Missing matrix APK: {apk.name}")
        self.adb("uninstall", PACKAGE, check=False)
        self.adb("install", "-r", apk)

    def clear_volatile_policy_state(self, timeout):
        # Package uninstall does not clear OS signing-key-indexed token caches.
        # Restart only the Android framework, retaining H_k/H_c, kernel mounts,
        # and adbd/port forwarding. This is outside every timed observation.
        old = self.adb("shell", "pidof", "system_server").strip()
        self.adb("root")
        self.adb("wait-for-device")
        self.adb("shell", "setprop", "ctl.restart", "zygote")
        deadline = time.monotonic() + min(timeout, 240)
        while time.monotonic() < deadline:
            current = self.adb("shell", "pidof", "system_server", check=False).strip()
            service = self.adb("shell", "service", "check", "aspin", check=False)
            package = self.adb("shell", "service", "check", "package", check=False)
            if current and current != old and "Service aspin: found" in service and "Service package: found" in package:
                return
            time.sleep(2)
        raise TimeoutError("Android framework did not recover after volatile-cache isolation")

    def observe(self, cell: dict, directory: Path, iterations: int, warmups: int, timeout: int):
        remote = f"/data/user/0/{PACKAGE}/files/{cell['file']}"
        self.adb("shell", "logcat", "-c")
        command = ["shell", "am", "start", "-S", "-W", "-n", f"{PACKAGE}/.MainActivity",
                   "--es", "benchmark_type", "rttcache", "--es", "output_csv", remote]
        for key, value in {"scheme": cell["Scheme"], "phase": cell["Phase"],
                           "policy_cache": cell["Cache"]}.items():
            command.extend(["--es", key, str(value)])
        for key, value in {"iterations": iterations, "warmups": warmups,
                           "added_rtt_ms": cell["Added_RTT_ms"], "repeat": cell["Repeat"]}.items():
            command.extend(["--ei", key, str(value)])
        self.adb(*command)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if "ready" in self.adb("shell", "su", "0", "sh", "-c", f"'test -f {remote} && echo ready'", check=False):
                destination = directory / cell["file"]
                self.adb("pull", remote, destination)
                summary.validate_cell(destination, cell, iterations, require_cache_audit=False)
                return
            logs = self.adb("logcat", "-d", "-s", "MainActivity:E", "*:S")
            if "RTT cache benchmark failed" in logs:
                raise RuntimeError(f"APK failed {cell['file']}: {logs[-2000:]}")
            time.sleep(1)
        raise TimeoutError(f"APK timed out: {cell['file']}")


def main():
    def stop_requested(*_):
        raise KeyboardInterrupt("RTT run interrupted; cleaning up isolated resources")
    signal.signal(signal.SIGTERM, stop_requested)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", required=True)
    parser.add_argument("--cert-dir", type=Path, required=True)
    parser.add_argument("--apk-dir", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--warmups", type=int, default=10)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--rtts", default="0,20,50,100,200")
    parser.add_argument("--seed", type=int, default=2027)
    parser.add_argument("--timeout", type=int, default=3600)
    args = parser.parse_args()
    if args.iterations < 1 or args.warmups < 0 or args.timeout < 1:
        parser.error("iterations/timeout must be positive and warmups nonnegative")
    cells = plan([int(value) for value in args.rtts.split(",")], args.repeats, args.seed)
    directory = args.run_dir.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    if (directory / "matrix.json").exists() or list(directory.glob("rtt-*.csv")):
        raise RuntimeError("Refusing to overwrite an existing RTT matrix")
    manifest = {"state": "planned", "iterations": args.iterations, "warmups": args.warmups,
                "repeats": args.repeats, "seed": args.seed, "cells": cells,
                "cold_definition": "debug forced two-token refresh; protected H_k/H_c retained",
                "timing": "time to TLS acceptance/policy rejection; application read separate",
                "dcp_hot_evidence": "independent NSC preload; server metadata audit",
                "dcp_cold": "NSC retrieves one directly signed pin policy during each handshake"}
    manifest["compatibility_cache_isolation"] = "Android framework restart per compatible cell; H_k/H_c and kernel/adb transport retained; not timed"
    (directory / "matrix.json").write_text(json.dumps(manifest, indent=2) + "\n")
    device = Device(args.device)
    with IsolatedRttLink(args.cert_dir, directory / "network") as link:
        previous = []
        for line in device.adb("reverse", "--list").splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[1] in {"tcp:80", "tcp:443", "tcp:19090"}:
                previous.append((parts[1], parts[2]))
        try:
            for source_port, target_port in link.host_ports.items():
                device.adb("reverse", f"tcp:{source_port}", f"tcp:{target_port}")
            block = None
            for index, cell in enumerate(cells, start=1):
                current = (cell["Repeat"], cell["Added_RTT_ms"], cell["Algorithm"], cell["Phase"])
                if current != block:
                    link.set_rtt(cell["Added_RTT_ms"])
                    link.set_profile(cell["Phase"])
                    block = current
                link.publish(ROOT, cell["Algorithm"], cell["Mode"])
                if cell["Mode"] == "compatible":
                    device.clear_volatile_policy_state(args.timeout)
                device.install(args.apk_dir, cell["Algorithm"], cell["Mode"])
                device.adb("shell", "setprop", "debug.aspin.dcp_cold",
                           "1" if cell["Mode"] == "dcp" and cell["Cache"] == "cold-forced-refresh" else "0")
                audit_log = link.work / "observations.jsonl"
                previous_lines = len(audit_log.read_text().splitlines()) if audit_log.exists() else 0
                print(f"[{index}/{len(cells)}] {cell['file']}", flush=True)
                device.observe(cell, directory, args.iterations, args.warmups, args.timeout)
                if cell["Mode"] == "dcp":
                    records = [json.loads(line) for line in audit_log.read_text().splitlines()[previous_lines:]]
                    requests = sum(record["uri"] == "/.well-known/DCPServerCertPin.jws" for record in records)
                    expected = 1 if cell["Cache"] == "hot" else args.iterations + args.warmups
                    (directory / cell["file"]).with_suffix(".cache.json").write_text(json.dumps({
                        "scheme": "DCP", "metadata_requests": requests, "expected_requests": expected,
                        "result": "PASS" if requests == expected else "FAIL"}) + "\n")
                    summary.validate_cell(directory / cell["file"], cell, args.iterations)
            print(summary.summarize(directory))
            manifest["state"] = "complete"
            (directory / "matrix.json").write_text(json.dumps(manifest, indent=2) + "\n")
        finally:
            device.adb("shell", "setprop", "debug.aspin.dcp_cold", "0", check=False)
            for port in link.host_ports:
                device.adb("reverse", "--remove", f"tcp:{port}", check=False)
            for source, target in previous:
                device.adb("reverse", source, target)


if __name__ == "__main__":
    main()
