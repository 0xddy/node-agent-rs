#!/usr/bin/env python3
"""Loopback-only FTP fixture with upload integrity and visibility evidence.

Use --read-limit BYTES_PER_SECOND to create per-data-connection backpressure
using pyftpdlib's asynchronous throttling (the control loop remains responsive).
Use --ftps for explicit TLS with mandatory AUTH TLS and protected data channels.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import threading
import time
import uuid

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, ThrottledDTPHandler
from pyftpdlib.servers import FTPServer


class Evidence:
    def __init__(self, path, poll_interval):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.output = open(path, "a", encoding="utf-8", buffering=1)
        self.lock = threading.RLock()
        self.active = {}
        self.stop = threading.Event()
        self.poll_interval = poll_interval
        self.observer = threading.Thread(target=self.observe, daemon=True)
        self.observer.start()

    def emit(self, event, **fields):
        record = {"event": event, "time_unix_ns": time.time_ns(),
                  "monotonic_ns": time.monotonic_ns(), **fields}
        with self.lock:
            self.output.write(json.dumps(record, sort_keys=True) + "\n")
            self.output.flush()
            if event in {"received", "incomplete", "server_ready", "server_stopped"}:
                os.fsync(self.output.fileno())

    def start_upload(self, session, path, mode):
        upload = {"transfer_id": uuid.uuid4().hex, "session": session,
                  "path": path, "started_ns": time.monotonic_ns(),
                  "last_size": None, "first_visible_ns": None,
                  "first_nonempty_ns": None}
        with self.lock:
            self.active[upload["transfer_id"]] = upload
            self.emit("stor", transfer_id=upload["transfer_id"],
                      session=session, path=path, mode=mode,
                      existed_before_stor=os.path.exists(path))
        return upload["transfer_id"]

    def snapshot(self, upload):
        try:
            size = os.path.getsize(upload["path"])
        except FileNotFoundError:
            return
        now = time.monotonic_ns()
        if upload["first_visible_ns"] is None:
            upload["first_visible_ns"] = now
        if size and upload["first_nonempty_ns"] is None:
            upload["first_nonempty_ns"] = now
        if size != upload["last_size"]:
            upload["last_size"] = size
            self.emit("visible_size", transfer_id=upload["transfer_id"],
                      session=upload["session"], path=upload["path"], bytes=size,
                      elapsed_ms=(now - upload["started_ns"]) / 1e6)

    def finish_upload(self, transfer_id, event, path):
        finished_ns = time.monotonic_ns()
        finished_unix_ns = time.time_ns()
        with self.lock:
            upload = self.active.pop(transfer_id, None)
            if upload:
                self.snapshot(upload)
        digest = hashlib.sha256()
        size = 0
        error = None
        try:
            with open(path, "rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    size += len(chunk)
                    digest.update(chunk)
        except OSError as exc:
            error = str(exc)
        fields = {"transfer_id": transfer_id, "path": path, "bytes": size,
                  "sha256": digest.hexdigest() if error is None else None,
                  "finished_unix_ns": finished_unix_ns}
        if error:
            fields["file_error"] = error
        if upload:
            fields.update(session=upload["session"],
                          duration_ms=(finished_ns - upload["started_ns"]) / 1e6,
                          first_visible_ms=None if upload["first_visible_ns"] is None
                          else (upload["first_visible_ns"] - upload["started_ns"]) / 1e6,
                          first_nonempty_ms=None if upload["first_nonempty_ns"] is None
                          else (upload["first_nonempty_ns"] - upload["started_ns"]) / 1e6)
        self.emit(event, **fields)

    def observe(self):
        while not self.stop.wait(self.poll_interval):
            with self.lock:
                for upload in self.active.values():
                    self.snapshot(upload)

    def close(self):
        self.stop.set()
        self.observer.join()
        self.emit("server_stopped")
        self.output.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="/fixture/ftp")
    parser.add_argument("--events", default="/fixture/ftp-events.jsonl")
    parser.add_argument("--ftps", action="store_true", help="require explicit FTPS and PROT P")
    parser.add_argument("--certfile", default="/fixture/ftp.pem",
                        help="combined test certificate/private key; generated if absent")
    parser.add_argument("--read-limit", type=int, default=0,
                        help="upload bytes/sec per data connection; 0 is unlimited")
    parser.add_argument("--poll-ms", type=int, default=25,
                        help="interval for observing files before upload completion")
    args = parser.parse_args()
    if args.read_limit < 0 or args.poll_ms <= 0:
        parser.error("read-limit must be nonnegative and poll-ms must be positive")
    Path(args.root).mkdir(parents=True, exist_ok=True)
    evidence = Evidence(args.events, args.poll_ms / 1000)

    if args.ftps:
        from OpenSSL import crypto
        from pyftpdlib.handlers import TLS_DTPHandler, TLS_FTPHandler

        certificate = Path(args.certfile)
        if not certificate.exists():
            certificate.parent.mkdir(parents=True, exist_ok=True)
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, 2048)
            cert = crypto.X509()
            cert.set_version(2)
            cert.set_serial_number(int.from_bytes(os.urandom(16), "big"))
            cert.get_subject().CN = "localhost"
            cert.gmtime_adj_notBefore(-60)
            cert.gmtime_adj_notAfter(7 * 24 * 3600)
            cert.set_issuer(cert.get_subject())
            cert.set_pubkey(key)
            cert.add_extensions([crypto.X509Extension(
                b"subjectAltName", False, b"DNS:localhost,IP:127.0.0.1")])
            cert.sign(key, "sha256")
            descriptor = os.open(certificate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
                output.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

        class DataHandler(ThrottledDTPHandler, TLS_DTPHandler):
            read_limit = args.read_limit
            timeout = 120

        control_handler = TLS_FTPHandler
    else:
        class DataHandler(ThrottledDTPHandler):
            read_limit = args.read_limit
            timeout = 120

        control_handler = FTPHandler

    class Handler(control_handler):
        dtp_handler = DataHandler
        certfile = args.certfile if args.ftps else None
        tls_control_required = args.ftps
        tls_data_required = args.ftps
        passive_ports = range(30000, 30101)
        masquerade_address = "127.0.0.1"
        timeout = 120
        banner = "node-agent-rs FTP integrity fixture"

        def on_connect(self):
            self.fixture_session = uuid.uuid4().hex
            self.fixture_transfer = None
            evidence.emit("connect", session=self.fixture_session,
                          remote_ip=self.remote_ip, remote_port=self.remote_port)

        def on_login(self, username):
            evidence.emit("login", session=self.fixture_session, username=username)

        def on_disconnect(self):
            with evidence.lock:
                upload = evidence.active.get(self.fixture_transfer)
            if upload:
                evidence.finish_upload(self.fixture_transfer, "incomplete", upload["path"])
                self.fixture_transfer = None
            evidence.emit("disconnect", session=self.fixture_session)

        def ftp_STOR(self, file, mode="w"):
            self.fixture_transfer = evidence.start_upload(self.fixture_session, file, mode)
            result = super().ftp_STOR(file, mode)
            with evidence.lock:
                upload = evidence.active.get(self.fixture_transfer)
                if upload:
                    evidence.snapshot(upload)
            if result is None:
                evidence.finish_upload(self.fixture_transfer, "stor_rejected", file)
                self.fixture_transfer = None
            return result

        def on_file_received(self, file):
            evidence.finish_upload(self.fixture_transfer, "received", file)
            self.fixture_transfer = None

        def on_incomplete_file_received(self, file):
            evidence.finish_upload(self.fixture_transfer, "incomplete", file)
            self.fixture_transfer = None

    authorizer = DummyAuthorizer()
    authorizer.add_user("fixture", "fixture", os.path.abspath(args.root), perm="elradfmwMT")
    Handler.authorizer = authorizer
    server = FTPServer(("127.0.0.1", 2121), Handler)
    server.max_cons = 256
    server.max_cons_per_ip = 128

    def shutdown(signum, frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, shutdown)
    evidence.emit("server_ready", host="127.0.0.1", port=2121,
                  root=os.path.abspath(args.root), read_limit=args.read_limit,
                  protocol="ftps" if args.ftps else "ftp",
                  visibility_poll_ms=args.poll_ms)
    try:
        server.serve_forever(timeout=0.1)
    finally:
        server.close_all()
        evidence.close()


if __name__ == "__main__":
    main()
