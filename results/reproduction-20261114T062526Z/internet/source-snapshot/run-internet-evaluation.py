#!/usr/bin/env python3
"""Fresh, sequential Internet-only evaluation cohort on the ASPin Pixel 8.

Launch this script in an independent background service. Never resumes a
historical result directory, flashes a phone, or copies authority private keys
to a server. DNS changes only via an explicit ASPIN_BENCHMARK_DNS override.
All builds use at most 24 workers. Transport failures remain failed samples.
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
SOURCE_PATTERNS = (
    '*.py',
    'ASPin/shared/**/*.java', 'ASPin/*/app/src/main/java/**/*.java',
    'ASPin/*/build.gradle*', 'ASPin/*/settings.gradle*', 'ASPin/*/gradle.properties',
    'ASPin/*/app/build.gradle*', 'ASPin/*/app/src/**/AndroidManifest.xml',
    'ASPin/*/app/src/**/res/**/*.xml', 'ASPin/*/gradle/wrapper/*',
    'ASPin/*/app/src/**/res/raw/*.pem',
    'ASPin/*/gradlew', 'ASPin/*/gradlew.bat',
    'signing/**/*.py', 'signing/**/*.sh',
    'signing/*/my-app-cert.pem', 'signing/*/my-app-pubkey.pem',
    'signing/*/my-claim-pubkey.pem', 'signing/*/my-dcp-pubkey.pem',
    'signing/*/my-dcp-pub.txt', 'signing/*/my-app-cert-scp-hash.txt',
    'realserver/etc/cert/*/real-cert.pem', 'realserver/etc/cert/*/real-chain.pem',
    'rogueserver/etc/cert/*/rogue-cert.pem', 'rogueserver/etc/cert/*/rogue-chain.pem',
    'remote-experiment/*.py',
)


def snapshot_sources(root, directory):
    """Keep bytes as well as hashes of the selected public experiment sources."""
    root = root.resolve()
    paths = sorted({path for pattern in SOURCE_PATTERNS
                    for path in root.glob(pattern) if path.is_file()})
    if not paths:
        raise ValueError('No experiment sources to archive')
    # Validate before creating a snapshot; never follow a source symlink into
    # private files or material outside the selected source tree.
    for path in paths:
        if any(part.is_symlink() for part in (path, *path.parents) if part != root):
            raise ValueError('Source snapshot does not allow symlinks: ' + str(path))
        path.resolve().relative_to(root)
    snapshot = directory / 'source-snapshot'
    snapshot.mkdir(exist_ok=False)
    hashes = {}
    for path in paths:
        relative = path.relative_to(root)
        content = path.read_bytes()
        target = snapshot / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        hashes[relative.as_posix()] = hashlib.sha256(content).hexdigest()
    return hashes


def check_sources_unchanged(root, hashes):
    for name, expected in hashes.items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected:
            raise ValueError('Experiment source changed after snapshot: ' + name)


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
                "historical_measurements_reused": False, "stages": [], "workers": 24,
                "transport_failures_kept": True,
                "dns_server_override": os.environ.get('ASPIN_BENCHMARK_DNS')}
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
        stage("fresh-policies", [py, ROOT / "gen-trust-artifacts.py"])
        # Pin-set XML is regenerated with the fresh fixtures. Retain the exact
        # public inputs that the following APK build consumes, not stale XML.
        manifest["source_sha256"] = snapshot_sources(ROOT, directory)
        manifest["source_snapshot"] = "source-snapshot"
        save()
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
        check_sources_unchanged(ROOT, manifest["source_sha256"])
        stage("connection-matrix", [py, ROOT / "run-remote-comparison.py", "--device", args.device,
              "--deployment", args.deployment, "--apk-dir", apks, "--run-dir", directory / "comparison",
              "--iterations", args.iterations, "--warmups", "3", "--schemes",
              "DCP", "TLS", "SCP", "ASPin", "ASPin-compatible", "--record-transport-failures"])
        stage("functional", [py, ROOT / "run-remote-policy-scenarios.py", "--device", args.device,
              "--deployment", args.deployment, "--apk-dir", apks, "--run-dir", directory / "functional",
              "--short-seconds", "60"])
        stage("public-cross", [py, ROOT / "run-public-cross-benchmark.py", "--device", args.device,
              "--deployment", args.cross_deployment, "--run-dir", directory / "public-cross",
              "--restore-apk", apks / "ASPin-es256.apk",
              "--iterations", args.iterations])
        check_sources_unchanged(ROOT, manifest["source_sha256"])
        manifest["state"] = "complete"
    except BaseException as error:
        manifest.update(state="failed", error=str(error))
        raise
    finally:
        manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
        save()


if __name__ == "__main__":
    main()
