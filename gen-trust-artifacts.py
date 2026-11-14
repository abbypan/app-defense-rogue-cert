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


def write_nsc_experiment_configs(repo_root, alg, scp_pin):
    app_source = repo_root / "ASPin" / alg / "app" / "src"
    scp_config = app_source / "scpBenchmark" / "res" / "xml" / "network_security_config.xml"
    dcp_config = app_source / "dcpBenchmark" / "res" / "xml" / "network_security_config.xml"
    common = f"""        <domain includeSubdomains=\"false\">{alg}.idouzi.top</domain>
        <trust-anchors>
            <certificates src=\"system\" />
            <certificates src=\"@raw/aspin_benchmark_ca\" />
        </trust-anchors>"""
    scp_config.parent.mkdir(parents=True, exist_ok=True)
    scp_config.write_text(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<network-security-config>\n"
        "    <domain-config cleartextTrafficPermitted=\"false\">\n"
        f"{common}\n"
        "        <pin-set>\n"
        f"            <pin digest=\"SHA-256\">{scp_pin}</pin>\n"
        "        </pin-set>\n"
        "    </domain-config>\n"
        "</network-security-config>\n",
        encoding="utf-8",
    )
    dcp_config.parent.mkdir(parents=True, exist_ok=True)
    dcp_config.write_text(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<network-security-config>\n"
        "    <domain-config cleartextTrafficPermitted=\"false\">\n"
        f"{common}\n"
        "        <dynamic-pin-set />\n"
        "    </domain-config>\n"
        "</network-security-config>\n",
        encoding="utf-8",
    )


def generate_for_algorithm(repo_root, alg):
    signing_dir = repo_root / "signing" / alg
    scp_generator = repo_root / "signing" / "gen_scp_hash.py"
    server_cert = repo_root / "realserver" / "etc" / "cert" / alg / "real-cert.pem"
    issuer_chain = repo_root / "realserver" / "etc" / "cert" / alg / "real-chain.pem"
    alg_well_known_dir = repo_root / "realserver" / "var" / "www" / alg / ".well-known"
    require_file(scp_generator, "SCP hash generator")
    require_file(signing_dir / "gen_jws_ClaimSigningKey.py", "ClaimSigningKey JWS generator")
    require_file(
        repo_root / "signing" / "gen_compat_ClaimSigningKey.py",
        "compatible-mode ClaimSigningKey JWS generator",
    )
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
        [sys.executable, "gen_jws_ClaimSigningKey.py"],
        f"{alg}: generate app-signing-key-rooted ClaimSigningKey JWS",
        signing_dir,
    )
    copy_file(
        signing_dir / "ClaimSigningKey.jws",
        signing_dir / "ClaimSigningKey.primary.jws",
    )
    run_checked(
        [sys.executable, str(repo_root / "signing" / "gen_compat_ClaimSigningKey.py")],
        f"{alg}: generate manifest-key-rooted compatible ClaimSigningKey JWS",
        signing_dir,
    )
    run_checked(
        [sys.executable, str(repo_root / "signing" / "gen_dcp_policy.py"), "--alg", alg,
         "--output", str(signing_dir / "DCPServerCertPin.jws")],
        f"{alg}: generate independently signed NSC DCP leaf-pin policy", signing_dir,
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
    scp_pin = (signing_dir / "my-app-cert-scp-hash.txt").read_text(
        encoding="ascii"
    ).strip()
    write_nsc_experiment_configs(repo_root, alg, scp_pin)

    print(f"Wrote {signing_dir / 'ClaimSigningKey.primary.jws'}")
    print(f"Wrote {signing_dir / 'ClaimSigningKey.compat.jws'}")
    print(f"Wrote {signing_dir / 'ServerCertClaim.jws'}")

    copy_file(
        signing_dir / "ServerCertClaim.jws",
        alg_well_known_dir / "ServerCertClaim.jws",
    )
    copy_file(signing_dir / "DCPServerCertPin.jws",
              alg_well_known_dir / "DCPServerCertPin.jws")
    copy_file(
        signing_dir / "ClaimSigningKey.primary.jws",
        alg_well_known_dir / "ClaimSigningKey.jws",
    )
    copy_file(
        signing_dir / "ClaimSigningKey.primary.jws",
        alg_well_known_dir / "ClaimSigningKey.primary.jws",
    )
    copy_file(
        signing_dir / "ClaimSigningKey.compat.jws",
        alg_well_known_dir / "ClaimSigningKey.compat.jws",
    )


def main():
    repo_root = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(
        description="Generate NSC SCP pins and primary/compatible ASPin JWS artifacts."
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
