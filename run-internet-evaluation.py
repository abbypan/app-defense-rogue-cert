#!/usr/bin/env python3
"""Fresh, sequential Internet-only evaluation cohort on the ASPin Pixel 8.

Launch this script in an independent background service. Never resumes a
historical result directory, flashes a phone, changes DNS, or copies authority
private keys to a server. All builds use at most 24 workers.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--device", default="3A201FDJH000GP")
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--cross-deployment", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=20)
    args = parser.parse_args()
    directory = args.run_dir.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    manifest = {"state": "running", "created_utc": datetime.now(timezone.utc).isoformat(),
                "transport": "Pixel 8 Wi-Fi Internet to public-CA HTTPS origins on hk:443",
                "historical_measurements_reused": False, "stages": [], "workers": 24}
    env = os.environ | {"JAVA_HOME": "/usr/lib/jvm/java-21-openjdk", "PYTHONUNBUFFERED": "1"}

    def save():
        (directory / "cohort.json").write_text(json.dumps(manifest, indent=2) + "\n")

    def stage(name, command, cwd=ROOT):
        item = {"name": name, "started_utc": datetime.now(timezone.utc).isoformat(),
                "state": "running"}
        manifest["stages"].append(item)
        save()
        print("Starting " + name, flush=True)
        with (directory / (name + ".log")).open("w") as log:
            result = subprocess.run(list(map(str, command)), cwd=cwd, env=env,
                                    stdout=log, stderr=subprocess.STDOUT)
        item.update(state="complete" if result.returncode == 0 else "failed",
                    finished_utc=datetime.now(timezone.utc).isoformat(), returncode=result.returncode)
        save()
        if result.returncode:
            raise RuntimeError(name + " failed; see its retained log")

    py = sys.executable
    apks = directory / "apks"
    try:
        manifest["source_sha256"] = {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for pattern in ("run-remote-*.py", "run-public-cross-benchmark.py", "ASPin/shared/**/*.java",
                            "ASPin/*/app/src/main/java/**/*.java", "remote-experiment/*.py")
            for path in ROOT.glob(pattern) if path.is_file()}
        stage("fresh-policies", [py, ROOT / "gen-trust-artifacts.py"])
        for variant in ("es256", "es384", "rsa3072", "rsa4096"):
            target = directory / "matrix-artifacts" / variant
            target.mkdir(parents=True)
            for filename in ("ClaimSigningKey.primary.jws", "ClaimSigningKey.compat.jws",
                             "ServerCertClaim.jws", "DCPServerCertPin.jws"):
                shutil.copyfile(ROOT / "signing" / variant / filename, target / filename)
        stage("publish-policies", [py, ROOT / "update-remote-policies.py", "--deployment", args.deployment])
        stage("build-four-modes", [py, ROOT / "gen-signed-apks.py", "--workers", "24",
              "--mode", "primary", "--mode", "scp", "--mode", "dcp", "--mode", "compatible",
              "--build-callers", "--output-dir", apks])
        project = ROOT / "ASPin/es256"
        stage("build-callers", ["./gradlew", "--no-daemon", "--max-workers=24",
              ":app:assembleCrossAppCaller", ":app:assembleCrossAppHidden"], project)
        stage("build-manifest-rotation", ["./gradlew", "--no-daemon", "--max-workers=24",
              "-PaspinPolicyPublicKeyFile=" + str(ROOT / "signing/es384/my-dcp-pub.txt"),
              ":app:assembleCompatibilityBenchmark"], project)
        rotated = directory / "rotated-apk"
        stage("sign-manifest-rotation", [py, ROOT / "gen-signed-apks.py", "--skip-build",
              "--variant", "es256", "--mode", "compatible", "--output-dir", rotated])
        shutil.copyfile(rotated / "ASPin-es256-compatible.apk", apks / "ASPin-es256-compatible-rotated-root.apk")
        stage("connection-matrix", [py, ROOT / "run-remote-comparison.py", "--device", args.device,
              "--deployment", args.deployment, "--apk-dir", apks, "--run-dir", directory / "comparison",
              "--iterations", args.iterations, "--warmups", "3", "--schemes",
              "DCP", "TLS", "SCP", "ASPin", "ASPin-compatible"])
        stage("functional", [py, ROOT / "run-remote-policy-scenarios.py", "--device", args.device,
              "--deployment", args.deployment, "--apk-dir", apks, "--run-dir", directory / "functional",
              "--short-seconds", "60"])
        stage("public-cross", [py, ROOT / "run-public-cross-benchmark.py", "--device", args.device,
              "--deployment", args.cross_deployment, "--run-dir", directory / "public-cross",
              "--iterations", args.iterations])
        manifest["state"] = "complete"
    except BaseException as error:
        manifest.update(state="failed", error=str(error))
        raise
    finally:
        manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
        save()


if __name__ == "__main__":
    main()
