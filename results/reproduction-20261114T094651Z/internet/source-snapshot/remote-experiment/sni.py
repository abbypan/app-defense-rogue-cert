#!/usr/bin/env python3
"""Scoped SNI cutover with an unchanged original config and rollback on failure."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import time


def run(arguments):
    return subprocess.run(arguments, check=True, capture_output=True, text=True)


def fingerprint(port, hostname):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Identity comparison only, not an ASPin test.
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=hostname) as connection:
            return hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest()


def native_identity(port, hostname):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        with ssl.create_default_context().wrap_socket(raw, server_hostname=hostname) as connection:
            certificate = connection.getpeercert()
            pem = ssl.DER_cert_to_PEM_cert(connection.getpeercert(binary_form=True)).encode()
    public = subprocess.run(["openssl", "x509", "-pubkey", "-noout"],
                            input=pem, capture_output=True, check=True).stdout
    return hashlib.sha256(public).hexdigest(), sorted(certificate["subjectAltName"])


def ready(port, hostname, expected=None):
    last = None
    for _ in range(20):
        try:
            value = fingerprint(port, hostname)
            if expected is not None and value != expected:
                raise RuntimeError("Existing TLS identity changed")
            return value
        except (OSError, RuntimeError) as error:
            last = error
            time.sleep(0.25)
    raise RuntimeError("TLS endpoint did not become ready") from last


def start(unit, arguments):
    run(["systemd-run", "--unit=" + unit, "--property=NoNewPrivileges=yes", *arguments])


def stop(unit):
    subprocess.run(["systemctl", "stop", unit], capture_output=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--old-pid", type=int)
    parser.add_argument("--restore", action="store_true")
    args = parser.parse_args()
    directory = args.directory.resolve()
    state_file = directory / "sni-state.json"
    if args.restore:
        state = json.loads(state_file.read_text())
        stop(state["front_unit"])
        start(state["restore_unit"], state["original_argv"])
        ready(443, "aspin-preserve.invalid", state["backend_fingerprint"])
        stop(state["backend_unit"])
        print("Original 443 TLS service restored; its configuration was never modified.")
        return
    if not args.old_pid or state_file.exists():
        parser.error("Supply the verified old PID; a prior cutover must be restored first")
    haproxy = shutil.which("haproxy") or "/usr/sbin/haproxy"
    if not Path(haproxy).is_file():
        parser.error("Install HAProxy before the SNI cutover")
    process = Path("/proc") / str(args.old_pid)
    original_executable = (process / "exe").resolve()
    if str(original_executable) != "/usr/local/share/overtls/overtls-bin":
        raise RuntimeError("Unexpected original 443 executable")
    argv = [value.decode() for value in (process / "cmdline").read_bytes().split(b"\0") if value]
    config_path = Path(argv[argv.index("-c") + 1])
    original = json.loads(config_path.read_text())
    if config_path != Path("/etc/overtls/config.json") or original["server_settings"]["listen_port"] != 443:
        raise RuntimeError("Unexpected original listener configuration")
    process_start = (process / "stat").read_text().split()[21]
    original_fingerprint = ready(443, "aspin-preserve.invalid")
    certificate = ssl._ssl._test_decode_cert(original["server_settings"]["certfile"])
    preserve_hostname = next(value for kind, value in certificate["subjectAltName"]
                             if kind == "DNS" and "*" not in value)
    manifest = json.loads((directory / "manifest.json").read_text())
    hosts = sorted(manifest["hosts"])
    if not hosts or any(not hostname.replace(".", "").replace("-", "").isalnum() for hostname in hosts):
        raise RuntimeError("Invalid SNI hostname set")
    tag = directory.name
    state = {"original_argv": argv, "original_fingerprint": original_fingerprint,
        "backend_unit": "aspin-previous-tls-" + tag,
        "front_unit": "aspin-sni-" + tag, "restore_unit": "aspin-restored-tls-" + tag}
    override = copy.deepcopy(original)
    override["server_settings"].update(listen_host="127.0.0.1", listen_port=10443)
    override_path = directory / "overtls-loopback.json"
    override_path.write_text(json.dumps(override))
    override_path.chmod(0o600)
    replacement = list(argv)
    replacement[replacement.index("-c") + 1] = str(override_path)
    start(state["backend_unit"], replacement)
    backend_fingerprint = ready(10443, "aspin-preserve.invalid")
    # A long-running process can still hold the previous leaf after automatic
    # renewal has replaced the files. Permit renewal only with identical SANs
    # and public key and successful native trust/hostname validation of BOTH.
    if native_identity(443, preserve_hostname) != native_identity(10443, preserve_hostname):
        raise RuntimeError("Existing TLS hostname or public key changed")
    state["backend_fingerprint"] = backend_fingerprint
    template = """global
    maxconn 1024
defaults
    mode tcp
    timeout connect 10s
    timeout client 5m
    timeout server 5m
frontend shared_tls
    bind 0.0.0.0:{port}
    tcp-request inspect-delay 5s
    tcp-request content accept if {{ req_ssl_hello_type 1 }}
    use_backend aspin_origin if {{ req_ssl_sni -i {hosts} }}
    default_backend previous_tls
backend aspin_origin
    server origin 127.0.0.1:8443
backend previous_tls
    server original 127.0.0.1:10443
"""
    config = directory / "haproxy.cfg"
    config.write_text(template.format(port=10444, hosts=" ".join(hosts)))
    run([haproxy, "-c", "-f", str(config)])
    start(state["front_unit"], [haproxy, "-W", "-db", "-f", str(config)])
    ready(10444, "aspin-preserve.invalid", backend_fingerprint)
    for hostname in hosts:
        if ready(10444, hostname) != ready(8443, hostname):
            raise RuntimeError("Experiment SNI route selected the wrong certificate")
    state_file.write_text(json.dumps(state, indent=2) + "\n")
    state_file.chmod(0o600)
    cutover_started = False
    try:
        if (process / "stat").read_text().split()[21] != process_start:
            raise RuntimeError("Original process changed before cutover")
        cutover_started = True
        # Stop only the verified TLS PID, NEVER ssh.service (its cgroup owner).
        os.kill(args.old_pid, signal.SIGTERM)
        config.write_text(template.format(port=443, hosts=" ".join(hosts)))
        run([haproxy, "-c", "-f", str(config)])
        run(["systemctl", "restart", state["front_unit"]])
        ready(443, "aspin-preserve.invalid", backend_fingerprint)
        for hostname in hosts:
            if ready(443, hostname) != ready(8443, hostname):
                raise RuntimeError("Public SNI route selected the wrong certificate")
    except Exception:
        if cutover_started:
            stop(state["front_unit"])
            start(state["restore_unit"], argv)
            ready(443, "aspin-preserve.invalid", backend_fingerprint)
        raise
    print(json.dumps({"status": "SNI routing active", "hosts": hosts,
        "original_certificate_unchanged": backend_fingerprint == original_fingerprint,
        "original_public_key_and_names_unchanged": True,
        "native_default_service_validation_passed": True, "original_config_unchanged": True,
        "front_unit": state["front_unit"]}, indent=2))


if __name__ == "__main__":
    main()
