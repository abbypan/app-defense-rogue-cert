#!/usr/bin/env python3
"""Isolated netem link; never applies a qdisc to lo, Wi-Fi, USB, or a default route.

The device reaches namespace-local Nginx/echo listeners through adb reverse and
a localhost TCP relay. Added RTT is split over the two veth egress directions;
actual device-side application echo RTT is measured separately by the APK.
"""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time


ALGORITHMS = ("es256", "es384", "rsa3072", "rsa4096")


def run(*args: str, root: bool = False, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run((["sudo", "-n"] if root else []) + list(args),
                          check=check, text=True, capture_output=True)


def nginx_path(path: Path) -> str:
    text = str(path.resolve())
    if any(character in text for character in ('"', '\\', '\n', '\r', '$')):
        raise ValueError("Unsupported character in Nginx fixture path")
    return f'"{text}"'


def available_subnet() -> ipaddress.IPv4Network:
    used = []
    for row in json.loads(run("ip", "-j", "route", "show", "table", "all").stdout):
        destination = row.get("dst", "default")
        if destination != "default":
            try:
                network = ipaddress.ip_network(destination, strict=False)
                if network.version == 4:
                    used.append(network)
            except ValueError:
                pass
    for _ in range(128):
        # RFC 2544 benchmarking space; no NAT or external/default route is added.
        offset = secrets.randbelow(32_768) * 4
        candidate = ipaddress.ip_network((int(ipaddress.ip_address("198.18.0.0")) + offset, 30))
        if not any(candidate.overlaps(network) for network in used):
            return candidate
    raise RuntimeError("No unused private benchmark /30 link found")


class Relay(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Forward(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with socket.create_connection(self.server.upstream, timeout=15) as peer:
                self.request.settimeout(30)
                peer.settimeout(30)
                self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                peer.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                def copy(source, destination):
                    try:
                        while data := source.recv(65_536):
                            destination.sendall(data)
                    except (OSError, TimeoutError):
                        pass
                    finally:
                        try:
                            destination.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass

                outbound = threading.Thread(target=copy, args=(self.request, peer), daemon=True)
                outbound.start()
                copy(peer, self.request)
                outbound.join(timeout=31)
        except (OSError, TimeoutError):
            pass  # The app records this as a transport error, never policy rejection.


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.request.settimeout(30)
        try:
            while data := self.request.recv(1024):
                self.request.sendall(data)
        except (OSError, TimeoutError):
            pass


class SilentMetadata(socketserver.BaseRequestHandler):
    def handle(self):
        # Accept the metadata request but withhold its response beyond the OS's
        # 10-second read timeout. Only the dedicated metadata upstream uses this.
        time.sleep(25)


class IsolatedRttLink:
    def __init__(self, certificate_dir: Path, evidence_dir: Path):
        self.certificates = certificate_dir.resolve()
        self.evidence = evidence_dir
        token = secrets.token_hex(4)
        self.namespace = f"aspin-rtt-{token}"
        self.host_interface = f"arh{token}"
        self.peer_interface = f"arp{token}"
        self.work = Path(tempfile.mkdtemp(prefix="aspin-rtt-link-"))
        self.work.chmod(0o755)
        self.web = self.work / "www"
        self.config = self.work / "nginx.conf"
        self.namespace_created = False
        self.link_created = False
        self.relays = []
        self.processes = []
        self.log_stream = None
        self.host_ports = {}
        self.phase = "real"
        self.policy_transport = "serve"

    def __enter__(self):
        try:
            for tool in ("ip", "tc", "nginx", "sudo"):
                if shutil.which(tool) is None:
                    raise RuntimeError(f"Required RTT-emulation tool missing: {tool}")
            run("true", root=True)
            subnet = available_subnet()
            self.host_ip, self.peer_ip = str(subnet[1]), str(subnet[2])
            run("ip", "netns", "add", self.namespace, root=True)
            self.namespace_created = True
            run("ip", "link", "add", self.host_interface, "type", "veth", "peer",
                "name", self.peer_interface, root=True)
            self.link_created = True
            run("ip", "link", "set", self.peer_interface, "netns", self.namespace, root=True)
            run("ip", "addr", "add", f"{self.host_ip}/30", "dev", self.host_interface, root=True)
            run("ip", "link", "set", self.host_interface, "up", root=True)
            self.ns("ip", "addr", "add", f"{self.peer_ip}/30", "dev", self.peer_interface)
            self.ns("ip", "link", "set", self.peer_interface, "up")
            self.ns("ip", "link", "set", "lo", "up")
            for algorithm in ALGORITHMS:
                directory = self.web / algorithm / ".well-known"
                directory.mkdir(parents=True)
                for item in (self.web, self.web / algorithm, directory):
                    item.chmod(0o755)
            self.evidence.mkdir(parents=True, exist_ok=True)
            self.log_stream = (self.work / "services.log").open("w")
            self.set_rtt(0)
            self.write_config("real")
            self.ns("nginx", "-t", "-p", str(self.work), "-c", str(self.config))
            self.spawn("nginx", "-p", str(self.work), "-c", str(self.config), "-g", "daemon off;")
            self.spawn(sys.executable, str(Path(__file__).resolve()), "--echo-server")
            for port in (80, 443, 19090):
                relay = Relay(("127.0.0.1", 0), Forward)
                relay.upstream = (self.peer_ip, port)
                self.relays.append(relay)
                self.host_ports[port] = relay.server_address[1]
                threading.Thread(target=relay.serve_forever, daemon=True).start()
            self.wait_profile("real")
            (self.evidence / "link.json").write_text(json.dumps({
                "transport": "adb-reverse/localhost-relay/dedicated-netem-veth/namespace-nginx",
                "namespace": self.namespace,
                "host_interface": self.host_interface,
                "peer_interface": self.peer_interface,
                "added_rtt_definition": "half on host veth egress plus half on peer egress",
                "calibration": "APK measures 20 one-byte echo RTTs outside timed samples",
                "loss_percent": 0, "jitter_ms": 0,
                "limitations": "controlled added delay, not a real WAN/mobile-radio experiment",
            }, indent=2) + "\n")
            return self
        except BaseException:
            self.close()
            raise

    def ns(self, *args: str):
        return run("ip", "netns", "exec", self.namespace, *args, root=True)

    def spawn(self, *args: str):
        self.processes.append(subprocess.Popen(
            ["sudo", "-n", "ip", "netns", "exec", self.namespace, *args],
            stdout=self.log_stream, stderr=self.log_stream))

    def set_rtt(self, milliseconds: int):
        if not 0 <= milliseconds <= 2_000:
            raise ValueError("Added RTT must be between 0 and 2000 ms")
        delay = f"{milliseconds / 2:g}ms"
        run("tc", "qdisc", "replace", "dev", self.host_interface, "root", "netem",
            "delay", delay, root=True)
        self.ns("tc", "qdisc", "replace", "dev", self.peer_interface, "root", "netem", "delay", delay)
        if self.evidence.exists():
            (self.evidence / f"qdisc-{milliseconds}ms.json").write_text(json.dumps({
                "added_rtt_ms": milliseconds,
                "host": json.loads(run("tc", "-j", "qdisc", "show", "dev", self.host_interface).stdout),
                "peer": json.loads(self.ns("tc", "-j", "qdisc", "show", "dev", self.peer_interface).stdout),
            }, indent=2) + "\n")

    def write_config(self, phase: str):
        if phase not in ("real", "rogue"):
            raise ValueError("Unknown certificate profile")
        prefix = "authorized" if phase == "real" else "unexpected"
        blocks = []
        for algorithm in ALGORITHMS:
            certificate = self.certificates / f"{prefix}-{algorithm}-fullchain.pem"
            key = self.certificates / f"{prefix}-{algorithm}.key"
            if not certificate.is_file() or not key.is_file():
                raise RuntimeError(f"Missing controlled certificate fixture: {prefix}-{algorithm}")
            blocks.append(f"""server {{
    listen 80; listen 443 ssl; server_name {algorithm}.idouzi.top;
    ssl_certificate {nginx_path(certificate)};
    ssl_certificate_key {nginx_path(key)};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache off; ssl_session_tickets off;
    root {nginx_path(self.web / algorithm)};
    location /.well-known/ {{ {self.metadata_directive()} }}
    location = /.__aspin-control {{ return 200 '{phase}|{self.policy_transport}'; }}
    location / {{ return 200 'ASPin RTT benchmark OK\\n'; }}
}}""")
        self.config.write_text(f"""worker_processes 1;
pid {nginx_path(self.work / 'nginx.pid')};
error_log {nginx_path(self.work / 'nginx-error.log')};
events {{ worker_connections 1024; }}
http {{
log_format observations escape=json '{{"tag":"$http_x_aspin_observation","uri":"$uri","status":$status}}';
access_log {nginx_path(self.work / 'observations.jsonl')} observations;
default_type application/octet-stream;
client_body_temp_path {nginx_path(self.work / 'client-body')};
keepalive_timeout 0;
{chr(10).join(blocks)}
}}
""")

    def wait_profile(self, phase: str):
        expected_file = self.certificates / f"{'authorized' if phase == 'real' else 'unexpected'}-es256.crt"
        expected = ssl.PEM_cert_to_DER_cert(expected_file.read_text())
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # Readiness only: compare exact fixture DER, not a substitute for APK validation.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        for _ in range(100):
            if any(process.poll() is not None for process in self.processes):
                raise RuntimeError("Namespace benchmark service exited; inspect temporary service log")
            try:
                with socket.create_connection((self.peer_ip, 443), timeout=15) as connection:
                    with context.wrap_socket(connection, server_hostname="es256.idouzi.top") as tls:
                        if tls.getpeercert(binary_form=True) == expected:
                            return
            except (OSError, ssl.SSLError):
                pass
            time.sleep(0.1)
        raise RuntimeError("Isolated Nginx did not activate the requested certificate profile")

    def set_profile(self, phase: str):
        self.phase = phase
        self.write_config(phase)
        self.ns("nginx", "-t", "-p", str(self.work), "-c", str(self.config))
        self.ns("nginx", "-p", str(self.work), "-c", str(self.config), "-s", "reload")
        self.wait_profile(phase)
        self.wait_control(phase, self.policy_transport)

    def wait_control(self, phase: str, transport: str):
        # The certificate can stay identical while metadata behavior changes.
        # Wait for the new worker configuration, not merely an open TLS port.
        for _ in range(100):
            connection = http.client.HTTPConnection(self.peer_ip, 80, timeout=2)
            try:
                connection.request("GET", "/.__aspin-control", headers={"Host": "es256.idouzi.top"})
                response = connection.getresponse()
                if response.status == 200 and response.read().decode("ascii") == f"{phase}|{transport}":
                    return
            except (OSError, http.client.HTTPException):
                pass
            finally:
                connection.close()
            time.sleep(0.05)
        raise RuntimeError("Namespace metadata profile did not activate")

    def metadata_directive(self):
        return {"serve": "try_files $uri =404;", "503": "return 503;",
                "timeout": "proxy_pass http://127.0.0.1:19091; proxy_read_timeout 25s;"}[self.policy_transport]

    def set_policy_transport(self, state: str):
        if state not in ("serve", "503", "timeout"):
            raise ValueError("Unknown metadata transport state")
        if state == "timeout" and not getattr(self, "silent_started", False):
            self.spawn(sys.executable, str(Path(__file__).resolve()), "--silent-metadata")
            # Wait for the local silent listener, not for an artificial result.
            for _ in range(100):
                try:
                    with socket.create_connection((self.peer_ip, 19091), timeout=1):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError("Metadata suppression listener did not start")
            self.silent_started = True
        self.policy_transport = state
        self.set_profile(self.phase)

    def publish_pair(self, algorithm: str, tk: str, tc: str):
        for name, value in (("ClaimSigningKey.jws", tk), ("ServerCertClaim.jws", tc)):
            destination = self.web / algorithm / ".well-known" / name
            pending = destination.with_suffix(".pending")
            pending.write_text(value, encoding="utf-8")
            pending.chmod(0o644)
            pending.replace(destination)

    def observation_count(self, tag: str):
        log = self.work / "observations.jsonl"
        return sum(json.loads(line).get("tag") == tag for line in log.read_text().splitlines()) if log.exists() else 0

    def publish(self, repository: Path, algorithm: str, mode: str):
        source = repository / "signing" / algorithm
        suffix = "compat" if mode == "compatible" else "primary"
        for original, name in ((f"ClaimSigningKey.{suffix}.jws", "ClaimSigningKey.jws"),
                               ("ServerCertClaim.jws", "ServerCertClaim.jws")):
            destination = self.web / algorithm / ".well-known" / name
            pending = destination.with_suffix(".pending")
            shutil.copyfile(source / original, pending)
            pending.chmod(0o644)
            pending.replace(destination)
        if mode == "dcp":
            run("python3", str(repository / "signing/gen_dcp_policy.py"), "--alg", algorithm,
                "--certificate", str(self.certificates / f"authorized-{algorithm}.crt"),
                "--output", str(self.web / algorithm / ".well-known/DCPServerCertPin.jws"))

    def close(self):
        for relay in self.relays:
            relay.shutdown()
            relay.server_close()
        if self.namespace_created:
            # Target only the unique namespace created by this object.
            result = run("ip", "netns", "pids", self.namespace, root=True, check=False)
            pids = result.stdout.split()
            if pids and all(pid.isdecimal() for pid in pids):
                run("kill", "-TERM", "--", *pids, root=True, check=False)
            for process in self.processes:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    raise RuntimeError("Namespace process would not stop; retaining resources for recovery")
            run("ip", "netns", "delete", self.namespace, root=True, check=False)
        if self.link_created:
            run("ip", "link", "delete", self.host_interface, root=True, check=False)
        if self.log_stream:
            self.log_stream.close()
        if self.evidence.exists():
            for filename in ("services.log", "nginx-error.log", "observations.jsonl"):
                try:
                    if (self.work / filename).is_file():
                        shutil.copyfile(self.work / filename, self.evidence / filename)
                except OSError:
                    pass  # Cleanup must not mask the original service/startup error.
        # Only this process-created temporary directory; never a repository root.
        if self.work.parent == Path(tempfile.gettempdir()) and self.work.name.startswith("aspin-rtt-link-"):
            shutil.rmtree(self.work)

    def __exit__(self, *_):
        self.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--echo-server", action="store_true")
    modes.add_argument("--silent-metadata", action="store_true")
    args = parser.parse_args()
    with Relay(("0.0.0.0", 19091 if args.silent_metadata else 19090),
               SilentMetadata if args.silent_metadata else Echo) as server:
        server.serve_forever()
