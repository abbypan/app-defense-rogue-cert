#!/usr/bin/env python3
"""Deploy only TLS credentials and public signed policies through an SSH alias."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from signing.cosign_claim_signing_key import cosign


ROOT = Path(__file__).resolve().parent
ALGORITHMS = {"es256": "ES256", "es384": "ES384", "rsa3072": "PS256", "rsa4096": "PS384"}


def check_tls_pair(chain_file, key_file):
    certificates = x509.load_pem_x509_certificates(chain_file.read_bytes())
    key = serialization.load_pem_private_key(key_file.read_bytes(), None)
    def spki(public):
        return public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if not certificates or spki(certificates[0].public_key()) != spki(key.public_key()):
        raise ValueError("TLS certificate and private key do not match")
    leaf = certificates[0]
    now = datetime.now(timezone.utc)
    if not leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc:
        raise ValueError("TLS certificate is not currently valid")
    return leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)


def prepare(stage):
    manifest = {"version": 1, "hosts": {}}
    for alg in (*ALGORITHMS, "dcp"):
        certificates = {}
        hostnames = None
        for phase, prefix, service in (("real", "real", "realserver"), ("rogue", "rogue", "rogueserver")):
            if alg == "dcp" and phase == "rogue":
                continue
            source = ROOT / service / "etc/cert" / alg
            chain, private = source / (prefix + "-fullchain.pem"), source / (prefix + "-privkey.pem")
            names = check_tls_pair(chain, private)
            if hostnames is not None and set(names) != set(hostnames):
                raise ValueError("Real and rogue phases must use identical DNS SANs")
            hostnames = names
            target = stage / "certificates" / alg / phase
            target.mkdir(parents=True, mode=0o700)
            shutil.copyfile(chain, target / "fullchain.pem")
            shutil.copyfile(private, target / "tls-key.pem")
            (target / "tls-key.pem").chmod(0o600)
            certificates[phase] = {"chain": str((target / "fullchain.pem").relative_to(stage)),
                                   "key": str((target / "tls-key.pem").relative_to(stage))}
        tokens = stage / "tokens" / alg
        tokens.mkdir(parents=True)
        if alg in ALGORITHMS:
            source = ROOT / "signing" / alg
            for filename in ("ClaimSigningKey.primary.jws", "ClaimSigningKey.compat.jws", "ServerCertClaim.jws", "DCPServerCertPin.jws"):
                shutil.copyfile(source / filename, tokens / filename)
            for mode, key_stem in (("primary", "my-app"), ("compat", "my-dcp")):
                token = (source / ("ClaimSigningKey." + mode + ".jws")).read_text()
                signers = [(algorithm, ROOT / "signing" / other / (key_stem + "-key.pem"),
                            ROOT / "signing" / other / (key_stem + "-pubkey.pem"))
                           for other, algorithm in ALGORITHMS.items() if other != alg]
                shared = json.loads(cosign(token, signers))
                # The target's matching signature is fourth, not hidden by an old cap.
                shared["signatures"] = shared["signatures"][1:] + shared["signatures"][:1]
                (tokens / ("ClaimSigningKey.shared." + mode + ".jws")).write_text(
                    json.dumps(shared, separators=(",", ":")) + "\n")
        for hostname in hostnames:
            if hostname in manifest["hosts"]:
                raise ValueError("Duplicate experiment hostname")
            manifest["hosts"][hostname] = {"algorithm": alg, "certificates": certificates,
                                           "tokens": str(tokens.relative_to(stage))}
    for filename in ("server.py", "sni.py", "control.py"):
        source = ROOT / "remote-experiment" / filename
        if source.exists():
            shutil.copyfile(source, stage / filename)
    (stage / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (stage / "state.json").write_text(json.dumps({"default": {
        "phase": "real", "mode": "primary", "metadata_fault": "none",
        "generation": "initial-real-primary"}, "hosts": {}}) + "\n")
    return manifest


def ssh(alias, arguments, **kwargs):
    command = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", alias,
               shlex.join(str(arg) for arg in arguments)]
    return subprocess.run(command, check=True, text=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh-host", default="hk")
    parser.add_argument("--remote-root", default="/opt/aspin-experiment")
    parser.add_argument("--results-dir", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", args.ssh_host):
        parser.error("Use an SSH configuration alias, not an arbitrary command")
    remote_root = Path(args.remote_root)
    if not remote_root.is_absolute() or len(remote_root.parts) < 3 or ".." in remote_root.parts:
        parser.error("Use a dedicated absolute experiment directory")
    args.results_dir.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    remote = remote_root / run_id
    with tempfile.TemporaryDirectory(prefix="aspin-remote-deploy-") as temporary:
        stage = Path(temporary) / "bundle"
        stage.mkdir(mode=0o700)
        manifest = prepare(stage)
        archive = Path(temporary) / "bundle.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for candidate in sorted(stage.rglob("*")):
                tar.add(candidate, arcname=str(candidate.relative_to(stage)), recursive=False)
        archive.chmod(0o600)
        summary = {"ssh_alias": args.ssh_host, "remote_dir": str(remote),
            "origin_unit": "aspin-origin-" + run_id,
            "hosts": sorted(manifest["hosts"]), "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "prepared_only": args.prepare_only, "android_e2e_executed": False}
        if not args.prepare_only:
            # Unrelated services/configuration are not copied or overwritten.
            ssh(args.ssh_host, ["install", "-d", "-m", "0700", str(remote)])
            subprocess.run(["scp", "-q", str(archive), args.ssh_host + ":" + str(remote / "bundle.tar.gz")], check=True)
            ssh(args.ssh_host, ["tar", "--no-same-owner", "-xzf", str(remote / "bundle.tar.gz"), "-C", str(remote)])
            ssh(args.ssh_host, ["rm", "--", str(remote / "bundle.tar.gz")])
            ssh(args.ssh_host, ["systemd-run", "--unit=" + summary["origin_unit"],
                "--property=WorkingDirectory=" + str(remote), "--property=NoNewPrivileges=yes",
                "--property=ProtectSystem=strict", "--property=PrivateTmp=yes",
                "/usr/bin/python3", str(remote / "server.py"), "--manifest", str(remote / "manifest.json"),
                "--state", str(remote / "state.json")])
        (args.results_dir / "deployment.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
