#!/usr/bin/env python3
"""HTTPS origin for the US-1518 acceptance page.

WebAuthn requires a secure context, so the page cannot be served over plain
HTTP from a non-loopback host. `localhost` counts as a trustworthy origin, so
127.0.0.1 would technically work -- but the epic asks for HTTPS with a
documented trust step, and a harness whose security posture differs from the
thing it is testing invites the question "did it only pass because the browser
was relaxed?". So this serves real TLS over a self-signed certificate and the
runner tells you exactly how to trust it.

The certificate is generated locally, never committed. `mkcert` is used when
present (it installs the CA into the system and browser trust stores, which is
the least-friction path); otherwise a self-signed cert is written to a
gitignored directory and the runner prints the exact openssl command to trust
it, or instructs the operator to pass --insecure to the browser.
"""

from __future__ import annotations

import http.server
import os
import shutil
import socket
import ssl
import subprocess
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PAGE = os.path.join(HERE, "page.html")

# Everything this generates is a build artefact and is gitignored.
CERT_DIR = os.path.join(HERE, ".cert")

# What THIS process generated, recorded at the moment it generated it.
#
# Cleanup removes exactly this set -- never `CERT_DIR` wholesale. The directory
# is the operator's: they may have parked a mkcert CA, a trusted copy of
# `localhost.pem`, or a browser profile there, and a run that rmtree'd the
# directory would take any of it with it. A file that was already on disk when
# we looked (an earlier run's cert, reused on purpose so the trust note and
# the fingerprint stay stable) is not ours to delete either. What we created,
# we take with us; what we found, we leave.
_GENERATED_FILES = set()
_GENERATED_DIRS = set()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, **kw)


def have_mkcert():
    return shutil.which("mkcert") is not None


def ensure_certificate(host="localhost"):
    """Return (certfile, keyfile, trust_note). Generates on first use."""
    os.makedirs(CERT_DIR, exist_ok=True)
    cert = os.path.join(CERT_DIR, "localhost.pem")
    key = os.path.join(CERT_DIR, "localhost-key.pem")
    note = ""

    if have_mkcert():
        ca = _run(["mkcert", "-install"])
        note = ("mkcert generated the certificate and installed its CA into the "
                "system trust store; the browser should accept it with no prompt. "
                + (ca.stdout.strip() or ca.stderr.strip()))
        if _run(["mkcert", "-cert-file", cert, "-key-file", key,
                 host, "127.0.0.1"]).returncode == 0:
            _GENERATED_FILES.update((cert, key))
            return cert, key, note
        note += " (mkcert generation failed; falling back to self-signed)"

    if not (os.path.exists(cert) and os.path.exists(key)):
        openssl = shutil.which("openssl") or "/usr/bin/openssl"
        conf = os.path.join(CERT_DIR, "openssl.cnf")
        with open(conf, "w") as f:
            f.write(
                "[req]\ndistinguished_name=dn\nx509_extensions=v3\n"
                "prompt=no\n[dn]\nCN=%s\n"
                "[v3]\nbasicConstraints=CA:FALSE\n"
                "keyUsage=digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\n"
                "subjectAltName=DNS:%s,IP:127.0.0.1\n" % (host, host)
            )
        _run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
              "-keyout", key, "-out", cert, "-days", "30",
              "-config", conf])
        os.chmod(key, 0o600)
        _GENERATED_FILES.update((cert, key, conf))

    note = (
        "Self-signed certificate written to " + CERT_DIR + ". The browser will "
        "warn unless you trust it. Either:\n"
        "  (a) import it:  openssl x509 -in " + cert + " -inform PEM -trustout "
        "cacert -out local-ca.pem\n"
        "      then add local-ca.pem to your browser/OS trust store; or\n"
        "  (b) launch the browser with --ignore-certificate-errors (the runner "
        "does this automatically in --browser-args).\n"
        "WebAuthn still runs; only the TLS trust decision is bypassed."
    )
    return cert, key, note


class AcceptanceHandler(http.server.BaseHTTPRequestHandler):
    """Serves the page. Also accepts the page POSTing its verdicts back, so a
    headless browser run needs no DevTools-protocol plumbing to be readable."""

    results = {}
    results_lock = threading.Lock()

    def log_message(self, *a):
        pass  # the runner prints a structured report instead

    def _send(self, code, body=b"", ctype="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            with open(PAGE, "rb") as f:
                self._send(200, f.read())
        elif path == "/results":
            import json
            with self.results_lock:
                payload = json.dumps(self.results).encode()
            self._send(200, payload, "application/json")
        elif path == "/favicon.ico":
            self._send(204)
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length)
        import json
        try:
            data = json.loads(body.decode())
        except ValueError as e:
            self._send(400, b"bad json", "text/plain")
            return
        if not isinstance(data, dict):
            self._send(400, b"expected a JSON object", "text/plain")
            return
        with self.results_lock:
            self.results.update(data)
        self._send(204)


class Server:
    """Serves the acceptance page over HTTPS on loopback.

    The URL uses the hostname `localhost`, NOT 127.0.0.1, and that is load
    bearing: the page derives its RP ID from location.hostname, and WebAuthn
    rejects an RP ID that is an IP literal ("SecurityError: This is an invalid
    domain"). Binding stays on 127.0.0.1 for safety; only the presented name is
    `localhost`, which resolves there anyway.
    """

    def __init__(self, host="127.0.0.1", port=None, certfile=None, keyfile=None,
                 url_host="localhost"):
        self.host = host
        self.url_host = url_host
        self.port = port or free_port()
        handler = AcceptanceHandler
        self.httpd = http.server.ThreadingHTTPServer((host, self.port), handler)
        self.httpd.daemon_threads = True
        if certfile:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile, keyfile)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.thread = None

    @property
    def url(self):
        return f"https://{self.url_host}:{self.port}/"

    def start(self):
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)
        self.thread.start()
        time.sleep(0.2)
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    @staticmethod
    def results():
        with AcceptanceHandler.results_lock:
            return dict(AcceptanceHandler.results)

    @staticmethod
    def reset_results():
        with AcceptanceHandler.results_lock:
            AcceptanceHandler.results.clear()


def user_data_dir():
    """Chrome profile for one run, claimed as ours only if it is not already
    there. A profile that outlived an earlier run is left alone: it is not
    proof of anything about this one, and it may be in use."""
    d = os.path.join(CERT_DIR, "udd")
    if not os.path.exists(d):
        _GENERATED_DIRS.add(d)
    return d


def cleanup_generated():
    """Remove what this process generated; return the paths actually removed.

    Safe to call on any exit path, repeatedly, and on a run that never created
    anything. Deliberately does NOT rmtree CERT_DIR -- see the note on
    _GENERATED_FILES. The directory itself is removed only when cleaning left
    it empty, which is the case for a normal run and the case that matters:
    an empty `.cert/` in the working tree is the leftover the tree-wide
    `no_private_key_material_is_committed` guard is there to catch.

    Best-effort by design. A cleanup that raises would replace the run's real
    result with a traceback about a temporary directory, so every removal is
    swallowed and reported instead.
    """
    removed = []
    for d in sorted(_GENERATED_DIRS, key=len, reverse=True):
        shutil.rmtree(d, ignore_errors=True)
        if not os.path.exists(d):
            removed.append(d)
    for f in sorted(_GENERATED_FILES, key=len, reverse=True):
        try:
            os.remove(f)
        except OSError:
            continue
        removed.append(f)
    _GENERATED_FILES.clear()
    _GENERATED_DIRS.clear()

    # The directory goes only if it is now empty, so anything the operator
    # left in it survives.
    if os.path.isdir(CERT_DIR) and not os.listdir(CERT_DIR):
        try:
            os.rmdir(CERT_DIR)
            removed.append(CERT_DIR)
        except OSError:
            pass
    return removed


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8443)
    args = ap.parse_args()
    cert, key, note = ensure_certificate()
    print(note)
    srv = Server(port=args.port, certfile=cert, keyfile=key).start()
    print(f"serving {srv.url}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.stop()
    finally:
        for p in cleanup_generated():
            print("removed " + p)