#!/usr/bin/env python3
"""Repeatable CSR issuance: realserver/Let's Encrypt, rogueserver/ZeroSSL.

Only GoDaddy DNS-01 challenge records are managed by Certbot. This program
never generates private keys, changes A/CNAME records, or reloads servers.
"""
import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

PROVIDERS = {
    "letsencrypt": ("realserver", "real", "https://acme-v02.api.letsencrypt.org/directory"),
    "zerossl": ("rogueserver", "rogue", "https://acme.zerossl.com/v2/DV90"),
}
TARGETS = ("dcp", "es256", "es384", "rsa3072", "rsa4096")
SECRET_NAMES = ("GODADDY_TOKEN", "GODADDY_KEY_ID", "GODADDY_KEY_SECRET",
                "ZEROSSL_EAB_KID", "ZEROSSL_EAB_HMAC_KEY")


def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def public_der(key):
    return key.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def private_file(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and not info.st_mode & 0o077, f"Unsafe credential permissions: {path}; require owner-only 0600")
    return path.read_text(encoding="utf-8")


def private_directory(path):
    require(not path.is_symlink(), f"Refusing symlink directory: {path}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(path.stat().st_uid == os.getuid() and not path.stat().st_mode & 0o022,
            f"Directory is owned by another user or writable by others: {path}")


def atomic_write(path, data, mode=0o600):
    require(not path.is_symlink(), f"Refusing symlink destination: {path}")
    fd, pending = tempfile.mkstemp(prefix=".acme-pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(pending, mode)
        os.replace(pending, path)
    finally:
        if os.path.exists(pending):
            os.unlink(pending)


def save_manifest(path, document):
    atomic_write(path, (json.dumps(document, indent=2) + "\n").encode())


def credential_environment(args):
    environment = dict(os.environ)
    config = Path(os.environ.get("XDG_CONFIG_HOME", Path.home()/".config"))
    files = args.env_file if args.env_file is not None else [
        config/"environment.d/90-aspin-zerossl.conf",
        config/"environment.d/91-aspin-godaddy-v3.conf",
    ]
    for path in files:
        if not path.exists() and args.env_file is None:
            continue
        for line in private_file(path).splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            name, separator, value = line.partition("=")
            name = name.strip()
            if separator and name in SECRET_NAMES and not environment.get(name):
                parsed = shlex.split(value, comments=False)
                require(len(parsed) == 1, f"Invalid environment value for {name}")
                environment[name] = parsed[0]
    if not environment.get("GODADDY_TOKEN"):
        credentials = args.godaddy_credentials or config/"aspin-acme/godaddy-v3.ini"
        for line in private_file(credentials).splitlines():
            name, separator, value = line.partition("=")
            if separator and name.strip() == "dns_godaddy_v3_token":
                environment["GODADDY_TOKEN"] = value.strip()
    token = environment.get("GODADDY_TOKEN", "")
    require(bool(re.fullmatch(r"gd_pat_[A-Za-z0-9_-]+", token)),
            "Set GODADDY_TOKEN to a GoDaddy v3 PAT (never pass a token on the command line)")
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    environment["PYTHONUNBUFFERED"] = "1"
    return environment


class Redactor:
    def __init__(self, environment):
        self.secrets = sorted({environment[name] for name in SECRET_NAMES if environment.get(name)},
                              key=len, reverse=True)

    def __call__(self, text):
        for secret in self.secrets:
            text = text.replace(secret, "[REDACTED]")
        return text


def certbot_entry(arguments):
    """Run installed Certbot with redaction active before it sets up logging."""
    redact = Redactor(os.environ)
    factory = logging.getLogRecordFactory()
    def safe_record(*args, **kwargs):
        record = factory(*args, **kwargs)
        record.msg, record.args = redact(record.getMessage()), ()
        return record
    logging.setLogRecordFactory(safe_record)
    original_exception = logging.Formatter.formatException
    logging.Formatter.formatException = lambda self, value: redact(original_exception(self, value))
    from certbot.main import main as certbot_main
    return certbot_main(arguments)


def certbot_python(explicit):
    if explicit:
        return str(explicit.expanduser().absolute())
    executable = shutil.which("certbot")
    require(executable is not None, "Install Certbot and certbot-dns-godaddy-v3, or set --certbot-python")
    with Path(executable).open(encoding="utf-8") as stream:
        first = stream.readline().strip()
    require(first.startswith("#!"), "Cannot locate Certbot's Python; set --certbot-python")
    parts = shlex.split(first[2:])
    interpreter = parts[0]
    if Path(interpreter).name == "env":
        require(len(parts) >= 2 and not parts[1].startswith("-"),
                "Complex Certbot shebang; set --certbot-python")
        interpreter = shutil.which(parts[1])
    require(interpreter is not None and "python" in Path(interpreter).name,
            "Cannot locate Certbot's Python; set --certbot-python")
    # Do not resolve a virtualenv Python symlink: its parent selects the venv.
    return str(interpreter)


def selected_account(state, provider, account):
    server = urlsplit(PROVIDERS[provider][2])
    directory = state/provider/"config/accounts"/server.netloc/server.path.strip("/")
    found = sorted(path.parent.name for path in directory.glob("*/regr.json")
                   if all((path.parent/name).is_file() for name in ("private_key.json", "meta.json")))
    if account:
        require(account in found, f"{provider}: requested account does not exist in {directory}")
        return account
    require(len(found) == 1, f"{provider}: require exactly one existing account in {directory}; "
            f"found {len(found)}. Select --{provider}-account if needed. No account will be registered.")
    return found[0]


@dataclass
class Job:
    provider: str
    target: str
    folder: Path
    csr_path: Path
    key_path: Path
    csr: object
    refresh: bool
    csr_hash: str
    key_hash: str

    @property
    def names(self):
        san = self.csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = san.get_values_for_type(x509.DNSName)
        require(bool(names) and len(names) == len(san), "CSR must contain only DNS SANs")
        require(len(names) == len(set(names)), "CSR contains duplicate DNS SANs")
        return sorted(names)

    @property
    def paths(self):
        names = ("real-cert.pem", "real-chain.pem", "real-fullchain.pem") if self.provider == "letsencrypt" else (
            "rogue-cert.crt", "rogue-ca.crt", "rogue-fullchain.pem")
        return tuple(self.folder/name for name in names)


def prepare_jobs(root, provider, targets, refresh):
    jobs = []
    require(not targets or len(targets) == len(set(targets)), "Duplicate --targets are not allowed")
    providers = PROVIDERS if provider == "all" else (provider,)
    for ca in providers:
        server, prefix, _ = PROVIDERS[ca]
        for target in (targets or TARGETS):
            if ca == "zerossl" and target == "dcp":
                require(provider == "all", "rogueserver has no dcp CSR")
                continue
            folder = root/server/"etc/cert"/target
            csr_path, key_path = folder/f"{prefix}-csr.pem", folder/f"{prefix}-privkey.pem"
            require(not csr_path.is_symlink() and not key_path.is_symlink(), "Refusing symlink CSR/private key")
            csr = x509.load_pem_x509_csr(csr_path.read_bytes())
            require(csr.is_signature_valid, f"{csr_path}: invalid CSR signature")
            key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            mismatch = public_der(csr.public_key()) != public_der(key.public_key())
            require(not mismatch or refresh, f"{csr_path}: CSR/private-key mismatch; "
                    "use --refresh-csr to regenerate the CSR while preserving the private key")
            if mismatch:
                builder = x509.CertificateSigningRequestBuilder().subject_name(csr.subject)
                for extension in csr.extensions:
                    builder = builder.add_extension(extension.value, extension.critical)
                csr = builder.sign(key, csr.signature_hash_algorithm)
            job = Job(ca, target, folder, csr_path, key_path, csr, mismatch,
                      fingerprint(csr_path), fingerprint(key_path))
            job.names  # Validate all selected inputs before the first request.
            require(not any(path.is_symlink() for path in job.paths), "Refusing symlink certificate destination")
            jobs.append(job)
    require(bool(jobs), "No CSR selected")
    return jobs


def prepare_shared_csr_jobs(csr_path, key_path, output, provider):
    """Submit exactly the same existing PKCS#10 request to each selected CA."""
    require(not csr_path.is_symlink() and not key_path.is_symlink(),
            "Refusing symlink CSR/private key")
    csr = x509.load_pem_x509_csr(csr_path.read_bytes())
    require(csr.is_signature_valid, "Shared CSR signature is invalid")
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    require(public_der(csr.public_key()) == public_der(key.public_key()),
            "Shared CSR/private-key mismatch; existing key and CSR were not changed")
    jobs = []
    for ca in (PROVIDERS if provider == "all" else (provider,)):
        folder = output / ca
        require(not folder.is_symlink(), "Refusing symlink certificate output directory")
        folder.mkdir(parents=True, exist_ok=True)
        job = Job(ca, "shared-csr", folder, csr_path, key_path, csr, False,
                  fingerprint(csr_path), fingerprint(key_path))
        job.names
        require(not any(path.is_symlink() for path in job.paths),
                "Refusing symlink certificate destination")
        jobs.append(job)
    return jobs


def verify_certificate(job, paths, ca_bundle=None):
    leaf_path, chain_path, fullchain_path = paths
    cert = x509.load_pem_x509_certificate(leaf_path.read_bytes())
    chain = x509.load_pem_x509_certificates(chain_path.read_bytes())
    fullchain = x509.load_pem_x509_certificates(fullchain_path.read_bytes())
    require(public_der(cert.public_key()) == public_der(job.csr.public_key()), "Certificate/CSR public-key mismatch")
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    require(len(names) == len(job.names) and sorted(names.get_values_for_type(x509.DNSName)) == job.names,
            "Certificate/CSR SAN mismatch")
    require(bool(chain) and fullchain == [cert, *chain], "Invalid chain/fullchain layout")
    cert.verify_directly_issued_by(chain[0])
    provider_name = "Let's Encrypt" if job.provider == "letsencrypt" else "ZeroSSL"
    require(provider_name in cert.issuer.rfc4514_string(), "Unexpected issuing CA")
    now = datetime.now(timezone.utc)
    require(cert.not_valid_before_utc <= now < cert.not_valid_after_utc, "Certificate is not currently valid")
    for hostname in job.names:
        command = ["openssl", "verify", "-purpose", "sslserver", "-verify_hostname", hostname,
                   "-untrusted", str(chain_path)]
        if ca_bundle:
            command += ["-CAfile", str(ca_bundle)]
        result = subprocess.run(command+[str(leaf_path)], capture_output=True, text=True)
        require(result.returncode == 0, "Native certificate-path/hostname verification failed: "+result.stderr.strip())
    return cert


def needs_renewal(job, args):
    if args.force:
        return True
    try:
        cert = verify_certificate(job, job.paths, args.ca_bundle)
        return cert.not_valid_after_utc <= datetime.now(timezone.utc)+timedelta(days=args.renew_before_days)
    except (OSError, ValueError, x509.ExtensionNotFound, InvalidSignature):
        return True


def install_files(outputs, backup):
    private_directory(backup)
    previous = {}
    for destination in outputs:
        require(not destination.is_symlink(), f"Refusing symlink destination: {destination}")
        previous[destination] = destination.read_bytes() if destination.exists() else None
        if previous[destination] is not None:
            atomic_write(backup/destination.name, previous[destination])
    changed = []
    try:
        for destination, content in outputs.items():
            atomic_write(destination, content, 0o644)
            changed.append(destination)
    except BaseException:
        for destination in reversed(changed):
            if previous[destination] is None:
                destination.unlink()
            else:
                atomic_write(destination, previous[destination], 0o644)
        raise


def run_certbot(python, arguments, environment, log_path, redact):
    command = [python, str(Path(__file__).resolve()), "_certbot", *arguments]
    with log_path.open("w", encoding="utf-8") as stream:
        process = subprocess.Popen(command, env=environment, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, start_new_session=True)
        try:
            for line in process.stdout:
                line = redact(line)
                print(line, end="", flush=True)
                stream.write(line)
                stream.flush()
            require(process.wait() == 0, "Certbot failed; existing certificates were not replaced")
        except BaseException:
            if process.poll() is None:
                # SIGINT lets Certbot clean up the DNS-01 record it created.
                import signal
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait(timeout=10)
            raise


@contextmanager
def exclusive_run(state):
    private_directory(state)
    lock_path = state/"request-server-certificates.lock"
    require(not lock_path.is_symlink(), "Refusing symlink lock file")
    with lock_path.open("a") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("Another certificate request run holds the state-directory lock") from error
        yield


def execute(args, environment, jobs, redact):
    actions = [(job, needs_renewal(job, args)) for job in jobs]
    accounts = {}
    for ca in {job.provider for job, renew in actions if renew}:
        accounts[ca] = selected_account(args.state_dir, ca, getattr(args, ca+"_account"))
    for job, renew in actions:
        action = "ISSUE" if renew else "SKIP (valid beyond renewal threshold)"
        repair = "; regenerate mismatched CSR using existing key" if job.refresh else ""
        print(f"{job.provider}/{job.target}: {action}{repair}; SAN={','.join(job.names)}", flush=True)
    if args.dry_run:
        print("Offline preflight complete: no ACME request, DNS mutation, CSR write, or certificate replacement.")
        return
    if not any(renew or job.refresh for job, renew in actions):
        print("All selected certificates are current; no ACME requests submitted.")
        return
    python = certbot_python(args.certbot_python)
    probe = subprocess.run([python, "-c", "from importlib.metadata import version; "
                            "print(version('certbot')); print(version('certbot-dns-godaddy-v3'))"],
                           env=environment, capture_output=True, text=True)
    require(probe.returncode == 0, "Certbot Python must contain certbot and certbot-dns-godaddy-v3")
    run_directory = args.state_dir/"runs"
    private_directory(run_directory)
    run = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-"), dir=run_directory))
    manifest = {"status": "running", "jobs": []}
    manifest_path = run/"manifest.json"
    print("Run directory:", run, flush=True)
    credentials = run/"godaddy-v3.ini"
    atomic_write(credentials, ("dns_godaddy_v3_token = "+environment["GODADDY_TOKEN"]+"\n").encode())
    try:
        for job, renew in actions:
            record = {"ca": job.provider, "target": job.target, "csr": str(job.csr_path),
                      "key_sha256": job.key_hash, "status": "pending", "dns_names": job.names}
            manifest["jobs"].append(record)
            save_manifest(manifest_path, manifest)
            require(fingerprint(job.key_path) == job.key_hash and fingerprint(job.csr_path) == job.csr_hash,
                    "CSR/private key changed after preflight")
            stage = run/job.provider/job.target
            stage.mkdir(mode=0o700, parents=True)
            backup = stage/"before"
            original_outputs = {path: fingerprint(path) for path in job.paths}
            if job.refresh:
                install_files({job.csr_path: job.csr.public_bytes(serialization.Encoding.PEM)}, backup)
                job.csr_hash = fingerprint(job.csr_path)
                record["csr_refreshed"] = True
            record["csr_sha256"] = job.csr_hash
            if not renew:
                record["status"] = "skipped_current"
                save_manifest(manifest_path, manifest)
                continue
            provider_state = args.state_dir/job.provider
            for name in ("work", "logs"):
                private_directory(provider_state/name)
            staged = tuple(stage/name for name in ("cert.pem", "chain.pem", "fullchain.pem"))
            command = ["certonly", "--non-interactive", "--server", PROVIDERS[job.provider][2],
                       "--account", accounts[job.provider],
                       "--config-dir", str(provider_state/"config"), "--work-dir", str(provider_state/"work"),
                       "--logs-dir", str(stage/"certbot-logs"),
                       "--authenticator", "dns-godaddy-v3", "--dns-godaddy-v3-credentials", str(credentials),
                       "--dns-godaddy-v3-propagation-seconds", str(args.propagation_seconds),
                       "--dns-godaddy-v3-ttl", str(args.dns_ttl), "--preferred-challenges", "dns",
                       "--csr", str(job.csr_path), "--cert-path", str(staged[0]),
                       "--chain-path", str(staged[1]), "--fullchain-path", str(staged[2])]
            record["status"] = "requesting"
            save_manifest(manifest_path, manifest)
            run_certbot(python, command, environment, stage/"certbot-output.log", redact)
            cert = verify_certificate(job, staged, args.ca_bundle)
            require(fingerprint(job.key_path) == job.key_hash and fingerprint(job.csr_path) == job.csr_hash,
                    "CSR/private key changed during issuance; new certificate left staged")
            require(all(fingerprint(path) == value for path, value in original_outputs.items()),
                    "Installed certificate files changed during issuance; new certificate left staged")
            install_files({path: source.read_bytes() for path, source in zip(job.paths, staged)}, backup)
            record.update(status="verified_and_installed", backup=str(backup),
                          installed_files=[str(path) for path in job.paths],
                          issuer=cert.issuer.rfc4514_string(), expires=cert.not_valid_after_utc.isoformat())
            save_manifest(manifest_path, manifest)
            print(f"PASS {job.provider}/{job.target}; expires {record['expires']}", flush=True)
        manifest["status"] = "complete"
    except BaseException as error:
        manifest["status"] = "interrupted" if isinstance(error, KeyboardInterrupt) else "failed"
        if manifest["jobs"]:
            manifest["jobs"][-1].update(status=manifest["status"], error=redact(str(error)))
        raise
    finally:
        save_manifest(manifest_path, manifest)
        credentials.unlink(missing_ok=True)
    print("Complete. Private keys unchanged; servers, A/CNAME records, JWS policies and APKs not modified.")
    print("CSR mode does not configure automatic renewal; rerun this script before expiry.")


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--ca", choices=("all", *PROVIDERS), default="all")
    result.add_argument("--targets", nargs="+", choices=TARGETS)
    result.add_argument("--csr", type=Path, help="One existing PKCS#10 request, shared by selected CAs")
    result.add_argument("--private-key", type=Path, help="Existing key matching --csr; never regenerated")
    result.add_argument("--output-dir", type=Path, help="Provider-specific certificate output under this directory")
    result.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent)
    result.add_argument("--state-dir", type=Path, default=Path(
        os.environ.get("XDG_DATA_HOME", Path.home()/".local/share"))/"aspin-acme")
    result.add_argument("--env-file", type=Path, action="append", help="Owner-only environment file; may repeat")
    result.add_argument("--godaddy-credentials", type=Path, help="Owner-only GoDaddy v3 credentials INI fallback")
    result.add_argument("--certbot-python", type=Path, default=os.environ.get("ASPIN_CERTBOT_PYTHON"))
    result.add_argument("--letsencrypt-account")
    result.add_argument("--zerossl-account")
    result.add_argument("--renew-before-days", type=int, default=30)
    result.add_argument("--propagation-seconds", type=int, default=120)
    result.add_argument("--dns-ttl", type=int, default=600)
    result.add_argument("--ca-bundle", type=Path, help="Override the native OpenSSL CA bundle")
    result.add_argument("--refresh-csr", action="store_true", help="Repair mismatched CSRs using existing private keys")
    result.add_argument("--force", action="store_true", help="Issue even if the current certificate is still valid")
    result.add_argument("--dry-run", action="store_true", help="Offline validation and plan only; NOT Certbot staging issuance")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    redact = Redactor(os.environ)
    try:
        require(args.renew_before_days >= 0, "--renew-before-days must be nonnegative")
        require(args.propagation_seconds >= 0 and 600 <= args.dns_ttl <= 86400,
                "Invalid propagation wait or DNS TTL (600..86400)")
        args.repo_root = args.repo_root.resolve()
        args.state_dir = args.state_dir.expanduser().resolve()
        require(not args.state_dir.is_relative_to(args.repo_root),
                "Keep ACME accounts, credentials, logs and backups outside the repository")
        environment = credential_environment(args)
        redact = Redactor(environment)
        if any((args.csr, args.private_key, args.output_dir)):
            require(all((args.csr, args.private_key, args.output_dir)),
                    "--csr, --private-key and --output-dir must be supplied together")
            require(not args.targets and not args.refresh_csr,
                    "Shared CSR mode cannot use --targets or --refresh-csr")
            jobs = prepare_shared_csr_jobs(args.csr.absolute(), args.private_key.absolute(),
                                           args.output_dir.resolve(), args.ca)
        else:
            jobs = prepare_jobs(args.repo_root, args.ca, args.targets, args.refresh_csr)
        if args.dry_run:
            execute(args, environment, jobs, redact)
        else:
            os.umask(0o077)
            with exclusive_run(args.state_dir):
                execute(args, environment, jobs, redact)
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print("ERROR: "+redact(str(error) or "interrupted"), file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == "__main__":
    if sys.argv[1:2] == ["_certbot"]:
        raise SystemExit(certbot_entry(sys.argv[2:]))
    raise SystemExit(main())
