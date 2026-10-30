#!/usr/bin/env python3
"""Create one CSR, configure its test A record, and obtain two public-CA leaves.

Never call dual end-entity issuance proof of a cross-signed intermediate. No new
ACME account is registered. Secrets are read using the existing private config.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import ipaddress
import json
import logging
from pathlib import Path
import subprocess
import sys

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("shared_csr_acme", ROOT / "request-server-certificates.py")
ACME = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ACME
SPEC.loader.exec_module(ACME)


def dns_records(session, zone, name, kind):
    records = []
    for page in range(1, 51):
        response = session.get("https://api.godaddy.com/v3/domains/zones/" + zone + "/dns-records",
            params={"type": kind, "name": name, "pageSize": 100, "page": page}, timeout=30)
        if response.status_code != 200:
            raise RuntimeError(f"GoDaddy read failed with HTTP {response.status_code}")
        body = response.json()
        records.extend(item for item in body.get("items", []) if item.get("type") == kind
                       and item.get("name", "").rstrip(".") in (name, name + "." + zone))
        if not any(link.get("rel") == "next" for link in body.get("links", [])): return records
    raise RuntimeError("GoDaddy pagination limit reached")


def configure_a(environment, zone, hostname, address, output, mutate):
    if not hostname.endswith("." + zone) or hostname == zone:
        raise ValueError("Use one explicit subdomain inside the selected zone")
    address = str(ipaddress.IPv4Address(address))
    name = hostname[:-(len(zone) + 1)]
    session = requests.Session()
    session.headers.update({"Authorization": "Bearer " + environment["GODADDY_TOKEN"],
                            "Accept": "application/json"})
    previous = {kind: dns_records(session, zone, name, kind) for kind in ("A", "AAAA", "CNAME")}
    if previous["AAAA"] or previous["CNAME"]:
        raise ValueError("Existing AAAA/CNAME conflicts with this IPv4-only experiment; no records changed")
    if previous["A"] and {record.get("data") for record in previous["A"]} != {address}:
        raise ValueError("Existing A record has another address; refusing to replace an unexpected target")
    if not previous["A"]:
        if not mutate: raise ValueError("A record is missing; use --configure-a to create the requested record")
        ACME.atomic_write(output / "dns-before.json", (json.dumps(previous, indent=2) + "\n").encode(), 0o644)
        response = session.post("https://api.godaddy.com/v3/domains/zones/" + zone + "/dns-records",
            json={"type": "A", "name": name, "data": address, "ttl": 600}, timeout=30)
        if response.status_code not in (200, 201, 202, 204):
            raise RuntimeError(f"GoDaddy A creation failed with HTTP {response.status_code}")
    after = dns_records(session, zone, name, "A")
    if not after or {record.get("data") for record in after} != {address}:
        raise RuntimeError("GoDaddy A-record verification failed")
    ACME.atomic_write(output / "dns-after.json", (json.dumps(after, indent=2) + "\n").encode(), 0o644)
    print(f"Verified A {hostname} -> {address}", flush=True)


def prepare_csr(output, hostname):
    key_path, csr_path = output / "server-privkey.pem", output / "server.csr.pem"
    if key_path.is_symlink() or csr_path.is_symlink(): raise ValueError("Symlink key/CSR refused")
    if key_path.exists() != csr_path.exists():
        raise ValueError("Incomplete existing key/CSR pair; refusing to overwrite either")
    if not key_path.exists():
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False).sign(key, hashes.SHA256())
        ACME.atomic_write(key_path, key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        ACME.atomic_write(csr_path, csr.public_bytes(serialization.Encoding.PEM), 0o644)
    csr = x509.load_pem_x509_csr(csr_path.read_bytes())
    if (not csr.is_signature_valid or csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) != [hostname]):
        raise ValueError("Existing CSR does not match the requested hostname")
    key = serialization.load_pem_private_key(key_path.read_bytes(), None)
    if ACME.public_der(key.public_key()) != ACME.public_der(csr.public_key()):
        raise ValueError("Existing CSR/private key mismatch")
    key_path.chmod(0o600)
    return key_path, csr_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hostname", default="cross.idouzi.top")
    parser.add_argument("--zone", default="idouzi.top")
    parser.add_argument("--address", default="64.90.5.66")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "public-cross/certificates")
    parser.add_argument("--configure-a", action="store_true", help="Create the A record if absent")
    parser.add_argument("--prepare-only", action="store_true", help="Prepare DNS/CSR, without requesting certificates")
    parser.add_argument("--ca", choices=("all", "letsencrypt", "zerossl"), default="all")
    parser.add_argument("--propagation-seconds", type=int, default=120)
    args = parser.parse_args()
    base = ACME.parser().parse_args([])
    environment = ACME.credential_environment(base)
    redact = ACME.Redactor(environment)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    try:
        for provider in ACME.PROVIDERS:
            if args.ca in ("all", provider): ACME.selected_account(base.state_dir, provider, None)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        output = args.output_dir.resolve()
        key, csr = prepare_csr(output, args.hostname)
        configure_a(environment, args.zone, args.hostname, args.address, output, args.configure_a)
        if args.prepare_only:
            print("One existing-key-matched PKCS#10 CSR prepared; no ACME requests sent")
            return
        command = [sys.executable, str(ROOT / "request-server-certificates.py"), "--ca", args.ca,
                   "--csr", str(csr), "--private-key", str(key), "--output-dir", str(output),
                   "--propagation-seconds", str(args.propagation_seconds)]
        subprocess.run(command, check=True, env=environment)
        document = {"hostname": args.hostname, "address": args.address,
                    "csr_sha256": ACME.fingerprint(csr), "created_utc": datetime.now(timezone.utc).isoformat(),
                    "certificate_kind": "same-CSR public-CA end-entity issuance; not a cross-signed intermediate",
                    "providers": {}}
        for provider in ACME.PROVIDERS:
            jobs = ACME.prepare_shared_csr_jobs(csr, key, output, provider)
            if not jobs[0].paths[0].exists(): continue
            cert = ACME.verify_certificate(jobs[0], jobs[0].paths)
            document["providers"][provider] = {"issuer": cert.issuer.rfc4514_string(),
                "subject": cert.subject.rfc4514_string(), "expires": cert.not_valid_after_utc.isoformat(),
                "leaf_sha256": cert.fingerprint(hashes.SHA256()).hex(),
                "spki_sha256": hashlib.sha256(ACME.public_der(cert.public_key())).hexdigest()}
        ACME.atomic_write(output / "issuance.json", (json.dumps(document, indent=2) + "\n").encode(), 0o644)
        print("Saved verified issuance metadata; no private key or credential value was printed")
    except Exception as error:
        raise SystemExit("ERROR: " + redact(str(error))) from None


if __name__ == "__main__": main()
