#!/usr/bin/env python3
import argparse
import shutil
import subprocess
import sys
from pathlib import Path


DEFAULT_ALGORITHMS = ("es256", "es384", "rsa3072", "rsa4096")


def run_checked(command, description, cwd):
    print(f"> {description}")
    result = subprocess.run(command, cwd=cwd)
    if result.returncode != 0:
        raise SystemExit(f"{description} failed with exit code {result.returncode}")


def require_file(path, label):
    if not path.exists():
        raise SystemExit(f"Missing {label}: {path}")


def copy_file(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    print(f"Copied {source} -> {destination}")


def generate_for_algorithm(repo_root, alg):
    signing_dir = repo_root / "signing" / alg
    app_resources_dir = repo_root / "ASPin" / alg / "app" / "src" / "main" / "resources"
    scp_generator = repo_root / "signing" / "gen_scp_hash.py"
    server_cert = repo_root / "realserver" / "etc" / "cert" / alg / "real-cert.pem"
    alg_well_known_dir = repo_root / "realserver" / "var" / "www" / alg / ".well-known"
    dcp_well_known_dir = repo_root / "realserver" / "var" / "www" / "dcp" / ".well-known"

    require_file(signing_dir / "gen_dcp.py", "DCP generator")
    require_file(scp_generator, "SCP hash generator")
    require_file(signing_dir / "gen_jwt_ClaimSigningKey.py", "ClaimSigningKey JWT generator")
    require_file(signing_dir / "gen_jwt_ServerCertClaim.py", "ServerCertClaim JWT generator")
    require_file(server_cert, "server certificate")
    require_file(signing_dir / "my-claim-key.pem", "claim signing key")
    require_file(signing_dir / "my-app-key.pem", "app signing key")
    require_file(signing_dir / "my-dcp-key.pem", "DCP signing key")

    run_checked(
        [
            sys.executable,
            str(scp_generator),
            str(server_cert),
            "--output",
            str(signing_dir / "my-app-cert-scp-hash.txt"),
        ],
        f"{alg}: generate my-app-cert-scp-hash.txt",
        signing_dir,
    )
    run_checked(
        [sys.executable, "gen_dcp.py", str(server_cert)],
        f"{alg}: generate DCPServerCertPin.json",
        signing_dir,
    )
    run_checked(
        [sys.executable, "gen_jwt_ClaimSigningKey.py"],
        f"{alg}: generate ClaimSigningKey.jwt",
        signing_dir,
    )
    run_checked(
        [sys.executable, "gen_jwt_ServerCertClaim.py", str(server_cert)],
        f"{alg}: generate ServerCertClaim.jwt",
        signing_dir,
    )

    print(f"Wrote {signing_dir / 'my-app-cert-scp-hash.txt'}")
    print(f"Wrote {signing_dir / 'DCPServerCertPin.json'}")
    print(f"Wrote {signing_dir / 'ClaimSigningKey.jwt'}")
    print(f"Wrote {signing_dir / 'ServerCertClaim.jwt'}")

    copy_file(
        signing_dir / "ServerCertClaim.jwt",
        alg_well_known_dir / "ServerCertClaim.jwt",
    )
    copy_file(
        signing_dir / "ClaimSigningKey.jwt",
        alg_well_known_dir / "ClaimSigningKey.jwt",
    )
    copy_file(
        signing_dir / "ServerCertClaim.jwt",
        app_resources_dir / "ServerCertClaim.jwt",
    )
    copy_file(
        signing_dir / "ClaimSigningKey.jwt",
        app_resources_dir / "ClaimSigningKey.jwt",
    )
    copy_file(
        signing_dir / "DCPServerCertPin.json",
        dcp_well_known_dir / f"DCPServerCertPin-{alg}.json",
    )


def main():
    repo_root = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(
        description="Generate DCPServerCertPin.json, ClaimSigningKey.jwt, and ServerCertClaim.jwt."
    )
    parser.add_argument(
        "--alg",
        action="append",
        choices=DEFAULT_ALGORITHMS,
        help="Algorithm to generate. Repeat for multiple algorithms. Defaults to all.",
    )
    args = parser.parse_args()

    algorithms = tuple(args.alg) if args.alg else DEFAULT_ALGORITHMS

    for alg in algorithms:
        generate_for_algorithm(repo_root, alg)


if __name__ == "__main__":
    main()
