#!/usr/bin/env python3
"""Isolated HTTPS test origin; policy/private app-signing keys never live here."""

import argparse
import copy
import json
import logging
from pathlib import Path
import re
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


TOKEN_PATHS = {
    "/.well-known/ClaimSigningKey.jws": "key_file",
    "/.well-known/ServerCertClaim.jws": "claim_file",
    "/.well-known/DCPServerCertPin.jws": "dcp_file",
}


def safe_file(root, relative):
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root.resolve()) or not candidate.is_file():
        raise ValueError("Invalid experiment artifact path")
    return candidate


def load_state(filename, hostname):
    state = json.loads(filename.read_text(encoding="utf-8"))
    profile = copy.deepcopy(state.get("default", {}))
    profile.update(state.get("hosts", {}).get(hostname, {}))
    defaults = {"phase": "real", "mode": "primary", "metadata_fault": "none",
                "claim_file": "ServerCertClaim.jws", "dcp_file": "DCPServerCertPin.jws",
                "generation": "initial"}
    profile = defaults | profile
    if profile["phase"] not in ("real", "rogue"):
        raise ValueError("Unknown certificate phase")
    if profile["mode"] not in ("primary", "compat"):
        raise ValueError("Unknown token mode")
    if profile["metadata_fault"] not in ("none", "503", "timeout"):
        raise ValueError("Unknown retrieval fault")
    profile.setdefault("key_file", "ClaimSigningKey." + profile["mode"] + ".jws")
    for name in ("key_file", "claim_file", "dcp_file"):
        if not re.fullmatch(r"[A-Za-z0-9._-]+\.jws", profile[name]):
            raise ValueError("Token selection must be a JWS basename")
    return profile


class Origin:
    def __init__(self, manifest, state):
        self.root = manifest.parent.resolve()
        self.manifest = json.loads(manifest.read_text(encoding="utf-8"))
        self.state = state
        self.contexts = {}
        for hostname, entry in self.manifest["hosts"].items():
            for phase, files in entry["certificates"].items():
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.load_cert_chain(safe_file(self.root, files["chain"]),
                                        safe_file(self.root, files["key"]))
                self.contexts[hostname, phase] = context

    def tls_context(self, forced_phase=None):
        # Separate listener context: never mutate the certificate contexts shared
        # by concurrent connections. A connection pins one state snapshot at SNI.
        initial = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        initial.minimum_version = ssl.TLSVersion.TLSv1_2

        def select(connection, hostname, ignored):
            if hostname not in self.manifest["hosts"]:
                raise ssl.SSLError("Unknown experiment SNI")
            profile = load_state(self.state, hostname)
            phase = forced_phase or profile["phase"]
            if (hostname, phase) not in self.contexts:
                raise ssl.SSLError("No certificate for this experiment phase")
            connection.context = self.contexts[hostname, phase]
            connection.aspin_hostname = hostname
            connection.aspin_profile = profile | {"phase": phase}

        initial.set_servername_callback(select)
        return initial


class ExperimentServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(20)
        return connection, address

    def process_request_thread(self, connection, address):
        # DCP fetches its policy while the business handshake is awaiting the
        # client's supplementary check. Handshaking in the accept loop would
        # serialize those sockets and deadlock this legitimate nested request.
        try:
            secured = self.tls.wrap_socket(connection, server_side=True)
            super().process_request_thread(secured, address)
        except (ssl.SSLError, OSError):
            # Rejected/abandoned handshakes are not application requests.
            connection.close()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ASPinExperiment"
    sys_version = ""

    def log_message(self, *args):
        pass

    def handle(self):
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError):
            # Certificate-only controls and rejected handshakes intentionally
            # close before HTTP. They must not create application-request logs.
            self.close_connection = True

    def reply(self, status, payload, kind="text/plain; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True
        profile = getattr(self.connection, "aspin_profile", {})
        observation = self.headers.get("X-ASPin-Observation", "")[:160]
        logging.info(json.dumps({"event": "http", "host": self.connection.aspin_hostname,
            "path": urlsplit(self.path).path, "status": status,
            "phase": profile.get("phase"), "generation": profile.get("generation"),
            "observation": observation}, sort_keys=True))

    def do_GET(self):
        hostname = self.connection.aspin_hostname
        authority = self.headers.get("Host", "").split(":", 1)[0].lower()
        if authority != hostname:
            return self.reply(421, b"Host/SNI mismatch\n")
        path = urlsplit(self.path).path
        profile = self.connection.aspin_profile
        if path in TOKEN_PATHS:
            fault = profile["metadata_fault"]
            if fault == "503":
                return self.reply(503, b"Controlled policy suppression\n")
            if fault == "timeout":
                time.sleep(15)  # Longer than the OS's 10-second metadata timeout.
                try:
                    self.reply(503, b"Controlled metadata timeout\n")
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass
                return
            directory = self.server.origin.manifest["hosts"][hostname]["tokens"]
            token = safe_file(self.server.origin.root,
                              str(Path(directory) / profile[TOKEN_PATHS[path]]))
            data = token.read_bytes()
            if len(data) > 1024 * 1024:
                return self.reply(500, b"Token exceeds experiment response bound\n")
            return self.reply(200, data, "application/jose+json")
        if path == "/":
            return self.reply(200, b"ASPin remote application response\n")
        return self.reply(404, b"Not an experiment endpoint\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--real-port", type=int, default=8443)
    parser.add_argument("--rogue-port", type=int, default=9443)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    origin = Origin(args.manifest.resolve(), args.state.resolve())
    for port, forced_phase in ((args.real_port, None), (args.rogue_port, "rogue")):
        server = ExperimentServer(("127.0.0.1", port), Handler)
        server.origin = origin
        server.tls = origin.tls_context(forced_phase)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    logging.info(json.dumps({"event": "ready", "hosts": sorted(origin.manifest["hosts"]),
                             "ports": [args.real_port, args.rogue_port]}))
    threading.Event().wait()


if __name__ == "__main__":
    main()
