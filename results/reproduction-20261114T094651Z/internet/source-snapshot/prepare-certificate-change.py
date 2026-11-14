#!/usr/bin/env python3
"""Prepare public-CA renewal/rekey fixtures without changing existing endpoints.

Certificate acquisition reuses the existing Certbot account and DNS-01 helper.
Only the two experiment CSRs are submitted; no account or A record is created.
Authority keys never leave this machine. TLS private keys remain Git-ignored.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parent
PHASES = ("real", "renewal", "rekey")


def spki(certificate):
    return certificate.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def names(certificate):
    return certificate.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)


def inspect_fixtures(directory, require_private_keys=True, at_time=None):
    """Reject CA migration, unchanged leaves, or an accidental non-rekey."""
    certificates, issuers, records = {}, {}, {}
    for phase in PHASES:
        folder = directory / phase
        chain = x509.load_pem_x509_certificates((folder / "fullchain.pem").read_bytes())
        if len(chain) < 2:
            raise ValueError("A full public-CA path with a direct issuer is required")
        leaf, issuer = chain[:2]
        leaf.verify_directly_issued_by(issuer)
        if require_private_keys:
            key = serialization.load_pem_private_key((folder / "tls-key.pem").read_bytes(), None)
            encoded = key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            if encoded != spki(leaf):
                raise ValueError("Certificate/private-key mismatch: " + phase)
        now = at_time or datetime.now(timezone.utc)
        if not leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc:
            raise ValueError("Certificate is not currently valid: " + phase)
        certificates[phase], issuers[phase] = leaf, issuer
        records[phase] = {"leaf_sha256": leaf.fingerprint(hashes.SHA256()).hex(),
            "serial": str(leaf.serial_number), "spki_sha256": sha(spki(leaf)),
            "subject": leaf.subject.rfc4514_string(), "san": names(leaf),
            "issuer_der_sha256": issuer.fingerprint(hashes.SHA256()).hex(),
            "not_before": leaf.not_valid_before_utc.isoformat(),
            "not_after": leaf.not_valid_after_utc.isoformat()}
        command = ["openssl", "verify", "-attime", str(int(now.timestamp())),
                   "-purpose", "sslserver", "-verify_hostname",
                   names(leaf)[0], "-untrusted", str(folder / "chain.pem"),
                   str(folder / "leaf.pem")]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            raise ValueError("Native public trust verification failed: " + result.stderr.strip())
    base = certificates["real"]
    if any((c.subject != base.subject or names(c) != names(base)) for c in certificates.values()):
        raise ValueError("All stages must preserve the same Subject/SAN")
    if len({c.fingerprint(hashes.SHA256()) for c in certificates.values()}) != 3:
        raise ValueError("Three distinct issued leaf certificates are required")
    if len({c.serial_number for c in certificates.values()}) != 3:
        raise ValueError("Each stage must have a distinct certificate serial")
    if len({c.public_bytes(serialization.Encoding.DER) for c in issuers.values()}) != 1:
        raise ValueError("Direct issuer DER differs: this is CA evolution, not certificate change")
    if spki(certificates["renewal"]) != spki(base):
        raise ValueError("Renewal must keep the TLS public key")
    if spki(certificates["rekey"]) == spki(base):
        raise ValueError("Rekey must replace the TLS public key")
    return records


def prepare(output, source):
    output.mkdir(parents=True, exist_ok=True)
    baseline = output / "real"
    baseline.mkdir(exist_ok=True)
    for source_name, target_name in (("real-cert.pem", "leaf.pem"),
            ("real-chain.pem", "chain.pem"), ("real-fullchain.pem", "fullchain.pem"),
            ("real-privkey.pem", "tls-key.pem"), ("real-csr.pem", "server.csr.pem")):
        target = baseline / target_name
        if not target.exists():
            shutil.copyfile(source / source_name, target)
        if target_name == "tls-key.pem":
            target.chmod(0o600)
    original = x509.load_pem_x509_csr((baseline / "server.csr.pem").read_bytes())
    leaf = x509.load_pem_x509_certificate((baseline / "leaf.pem").read_bytes())
    if not original.is_signature_valid or spki(original) != spki(leaf):
        raise ValueError("Baseline certificate and CSR must use the same key")
    if len(names(original)) != 1 or names(original) != names(leaf):
        raise ValueError("Use an existing one-host CSR matching the baseline certificate")
    for phase in ("renewal", "rekey", "alternate-rekey"):
        folder = output / phase
        folder.mkdir(exist_ok=True)
        key_path, csr_path = folder / "tls-key.pem", folder / "server.csr.pem"
        if key_path.exists() != csr_path.exists():
            raise ValueError("Incomplete private-key/CSR fixture: " + phase)
        if not key_path.exists():
            if phase == "renewal":
                shutil.copyfile(baseline / "tls-key.pem", key_path)
                shutil.copyfile(baseline / "server.csr.pem", csr_path)
            else:
                key = ec.generate_private_key(ec.SECP256R1())
                builder = x509.CertificateSigningRequestBuilder().subject_name(original.subject)
                for extension in original.extensions:
                    builder = builder.add_extension(extension.value, extension.critical)
                csr = builder.sign(key, hashes.SHA256())
                key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
        key_path.chmod(0o600)
        ignored = subprocess.run(["git", "check-ignore", "--quiet", str(key_path)], cwd=ROOT)
        if key_path.is_relative_to(ROOT) and ignored.returncode:
            raise ValueError("Experiment TLS private key must be excluded from Git")
    return names(leaf)[0]


def select_triplet(pool):
    """Pick two same-key leaves and a different-key leaf under one exact CA.

    Selection concerns fixture eligibility, not measured device outcomes. The
    source certificates and failed issuer-matching attempts remain archived.
    """
    eligible = {}
    for label, folder in pool.items():
        chain = x509.load_pem_x509_certificates((folder / "fullchain.pem").read_bytes())
        chain[0].verify_directly_issued_by(chain[1])
        eligible[label] = chain
    for a, first in eligible.items():
        for b, second in eligible.items():
            if (a == b or spki(first[0]) != spki(second[0])
                    or first[0].serial_number == second[0].serial_number
                    or first[1].public_bytes(serialization.Encoding.DER)
                    != second[1].public_bytes(serialization.Encoding.DER)):
                continue
            for c, third in eligible.items():
                if (spki(first[0]) != spki(third[0])
                        and first[1].public_bytes(serialization.Encoding.DER)
                        == third[1].public_bytes(serialization.Encoding.DER)
                        and first[0].subject == second[0].subject == third[0].subject
                        and names(first[0]) == names(second[0]) == names(third[0])):
                    return {"real": a, "renewal": b, "rekey": c}
    raise ValueError("No same-direct-issuer renewal/rekey triplet exists; no device run is permitted")


def select_issued_fixtures(directory):
    sources = {
        "original": (directory / "real", directory / "real"),
        "same-key-renewal": (directory / "renewal", directory / "renewal"),
        "first-new-key": (directory / "rekey/issued/letsencrypt", directory / "rekey"),
        "second-new-key-order": (directory / "rekey/issued-attempt-2/letsencrypt", directory / "rekey"),
        "second-new-key": (directory / "alternate-rekey/issued/letsencrypt", directory / "alternate-rekey"),
    }
    pool = {}
    for label, (certificates, credentials) in sources.items():
        folder = directory / "issuance-pool" / label
        if not folder.exists():
            folder.mkdir(parents=True)
            mapping = (("leaf.pem", "leaf.pem"), ("chain.pem", "chain.pem"), ("fullchain.pem", "fullchain.pem"))
            if "issued" in str(certificates.relative_to(directory)):
                mapping = (("real-cert.pem", "leaf.pem"), ("real-chain.pem", "chain.pem"),
                           ("real-fullchain.pem", "fullchain.pem"))
            for source, target in mapping:
                shutil.copyfile(certificates / source, folder / target)
            for name in ("tls-key.pem", "server.csr.pem"):
                shutil.copyfile(credentials / name, folder / name)
            (folder / "tls-key.pem").chmod(0o600)
        pool[label] = folder
    selected = select_triplet(pool)
    for phase, label in selected.items():
        for filename in ("leaf.pem", "chain.pem", "fullchain.pem", "tls-key.pem", "server.csr.pem"):
            shutil.copyfile(pool[label] / filename, directory / phase / filename)
        (directory / phase / "tls-key.pem").chmod(0o600)
    return selected


def write_scp_resources(directory):
    leaf = x509.load_pem_x509_certificate((directory / "real/leaf.pem").read_bytes())
    tree = ET.parse(ROOT / "ASPin/es256/app/src/scpBenchmark/res/xml/network_security_config.xml")
    import base64
    for pin in tree.iter("pin"):
        pin.text = base64.b64encode(hashlib.sha256(spki(leaf)).digest()).decode()
    target = directory.parent / "scp-res/xml/network_security_config.xml"
    target.parent.mkdir(parents=True, exist_ok=True)
    tree.write(target, encoding="utf-8", xml_declaration=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--baseline-dir", type=Path, default=ROOT / "realserver/etc/cert/es256")
    parser.add_argument("--issue", action="store_true", help="Submit both CSRs using the existing account")
    parser.add_argument("--rekey-attempt", type=int, choices=(1, 2, 3), default=1,
                        help="Explicit bounded issuance attempt; attempt three uses a second fresh TLS key")
    args = parser.parse_args()
    directory = args.output_dir.resolve()
    host = prepare(directory, args.baseline_dir.resolve())
    metadata = {"state": "prepared", "created_utc": datetime.now(timezone.utc).isoformat(),
                "hostname": host, "public_ca": "letsencrypt", "new_account": False,
                "dns_a_records_modified": False}
    manifest = directory / "fixtures.json"
    try:
        if args.issue:
            metadata["state"] = "requesting"
            manifest.write_text(json.dumps(metadata, indent=2) + "\n")
            phases = ("renewal", "rekey", "alternate-rekey") if args.rekey_attempt == 3 else ("renewal", "rekey")
            for phase in phases:
                folder = directory / phase
                print("Requesting public-CA " + phase + " certificate", flush=True)
                issued_name = ("issued-attempt-2" if phase == "rekey" and args.rekey_attempt >= 2
                               else "issued")
                subprocess.run([sys.executable, str(ROOT / "request-server-certificates.py"),
                    "--ca", "letsencrypt", "--csr", str(folder / "server.csr.pem"),
                    "--private-key", str(folder / "tls-key.pem"),
                    "--output-dir", str(folder / issued_name)], check=True)
                issued = folder / issued_name / "letsencrypt"
                for source, target in (("real-cert.pem", "leaf.pem"),
                        ("real-chain.pem", "chain.pem"), ("real-fullchain.pem", "fullchain.pem")):
                    shutil.copyfile(issued / source, folder / target)
            if args.rekey_attempt == 3:
                metadata["selected_issuances"] = select_issued_fixtures(directory)
            metadata.update(state="complete", certificates=inspect_fixtures(directory),
                            rekey_issuance_attempt=args.rekey_attempt)
            write_scp_resources(directory)
            print("PASS: distinct leaves, unchanged names and exact direct issuer, renewal/rekey keys verified")
    except BaseException as error:
        metadata.update(state="failed", error=str(error))
        raise
    finally:
        manifest.write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    main()
