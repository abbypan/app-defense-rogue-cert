#!/usr/bin/env python3
import argparse
import re
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


def update_scp_verifier_sources(repo_root):
    pins = {}
    for alg in DEFAULT_ALGORITHMS:
        pin_path = repo_root / "signing" / alg / "my-app-cert-scp-hash.txt"
        require_file(pin_path, f"{alg} SCP certificate hash")
        pin = pin_path.read_text(encoding="utf-8").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", pin):
            raise SystemExit(f"Invalid SHA-256 SCP certificate hash: {pin_path}")
        pins[alg] = pin

    for variant in DEFAULT_ALGORITHMS:
        source_path = (
            repo_root
            / "ASPin"
            / variant
            / "app"
            / "src"
            / "main"
            / "java"
            / "com"
            / "cert"
            / "aspin"
            / "SCPVerifier.java"
        )
        require_file(source_path, f"{variant} SCP verifier")
        source = source_path.read_text(encoding="utf-8")
        updated = source
        for alg, pin in pins.items():
            pattern = (
                rf'(pins\.put\("{re.escape(alg)}\.idouzi\.top", ")'
                rf'[0-9a-f]{{64}}("\);)'
            )
            updated, replacements = re.subn(pattern, rf"\g<1>{pin}\g<2>", updated)
            if replacements != 1:
                raise SystemExit(
                    f"Expected one {alg} SCP pin in {source_path}, found {replacements}"
                )
        updated, replacements = re.subn(
            r'(return ")[0-9a-f]{64}(";)',
            rf"\g<1>{pins['es256']}\g<2>",
            updated,
        )
        if replacements != 1:
            raise SystemExit(
                f"Expected one default SCP pin in {source_path}, found {replacements}"
            )
        source_path.write_text(updated, encoding="utf-8")
        print(f"Updated SCP pins in {source_path}")


def generate_for_algorithm(repo_root, alg):
    signing_dir = repo_root / "signing" / alg
    app_resources_dir = repo_root / "ASPin" / alg / "app" / "src" / "main" / "resources"
    scp_generator = repo_root / "signing" / "gen_scp_hash.py"
    server_cert = repo_root / "realserver" / "etc" / "cert" / alg / "real-cert.pem"
    issuer_chain = repo_root / "realserver" / "etc" / "cert" / alg / "real-chain.pem"
    alg_well_known_dir = repo_root / "realserver" / "var" / "www" / alg / ".well-known"
    dcp_well_known_dir = repo_root / "realserver" / "var" / "www" / "dcp" / ".well-known"

    require_file(signing_dir / "gen_dcp.py", "DCP generator")
    require_file(scp_generator, "SCP hash generator")
    require_file(signing_dir / "gen_jws_ClaimSigningKey.py", "ClaimSigningKey JWS generator")
    require_file(signing_dir / "gen_jws_ServerCertClaim.py", "ServerCertClaim JWS generator")
    require_file(server_cert, "server certificate")
    require_file(issuer_chain, "server issuer chain")
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
        [sys.executable, "gen_jws_ClaimSigningKey.py"],
        f"{alg}: generate ClaimSigningKey.jws",
        signing_dir,
    )
    run_checked(
        [
            sys.executable,
            "gen_jws_ServerCertClaim.py",
            str(server_cert),
            str(issuer_chain),
        ],
        f"{alg}: generate ServerCertClaim.jws",
        signing_dir,
    )
    run_checked(
        [sys.executable, str(repo_root / "check-trust-artifacts.py"), "--alg", alg],
        f"{alg}: validate ASPin token schema, trust anchors, and signatures",
        repo_root,
    )

    print(f"Wrote {signing_dir / 'my-app-cert-scp-hash.txt'}")
    print(f"Wrote {signing_dir / 'DCPServerCertPin.json'}")
    print(f"Wrote {signing_dir / 'ClaimSigningKey.jws'}")
    print(f"Wrote {signing_dir / 'ServerCertClaim.jws'}")

    copy_file(
        signing_dir / "ServerCertClaim.jws",
        alg_well_known_dir / "ServerCertClaim.jws",
    )
    copy_file(
        signing_dir / "ClaimSigningKey.jws",
        alg_well_known_dir / "ClaimSigningKey.jws",
    )
    copy_file(
        signing_dir / "ServerCertClaim.jws",
        app_resources_dir / "ServerCertClaim.jws",
    )
    copy_file(
        signing_dir / "ClaimSigningKey.jws",
        app_resources_dir / "ClaimSigningKey.jws",
    )
    copy_file(
        signing_dir / "DCPServerCertPin.json",
        dcp_well_known_dir / f"DCPServerCertPin-{alg}.json",
    )


def main():
    repo_root = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(
        description="Generate DCPServerCertPin.json, ClaimSigningKey.jws, and ServerCertClaim.jws."
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
    update_scp_verifier_sources(repo_root)


if __name__ == "__main__":
    main()
