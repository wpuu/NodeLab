"""TEST ONLY: a local CONNECT/TLS/controller substitute, not a proxy protocol.

Route rows are deliberately synthetic. This must NEVER count as Mihomo proof.
All listeners are loopback. Credentials are read only from the private YAML.
"""
import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import socketserver
import ssl
import threading
from uuid import uuid4

import yaml

parser = argparse.ArgumentParser()
parser.add_argument("-t", action="store_true")
parser.add_argument("-d")
parser.add_argument("-f")
args = parser.parse_args()
with open(args.f, encoding="utf-8") as stream:
    config = yaml.safe_load(stream)
if config["proxies"][0]["server"] != "127.0.0.1":
    raise SystemExit(2)
if args.t:
    raise SystemExit(0)

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.environ["NODELAB_FIXTURE_CERT"], os.environ["NODELAB_FIXTURE_KEY"])
active = {}
lock = threading.Lock()


class Controller(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("Authorization") != "Bearer " + config["secret"]:
            self.send_response(401)
            self.end_headers()
            return
        release = []
        if self.path == "/configs":
            payload = {"mode": "rule"}
        elif self.path == "/proxies":
            payload = {"proxies": {"NODE": {"type": "Trojan"},
                "PROBE": {"type": "Selector", "now": "NODE", "all": ["NODE"]}}}
        elif self.path == "/rules":
            payload = {"rules": [{"index": 0, "type": "Match", "payload": "", "proxy": "PROBE"}]}
        elif self.path == "/connections":
            with lock:
                payload = {"connections": [value[0] for value in active.values()] or None}
                release = [value[1] for value in active.values()]
        else:
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        for event in release:
            event.set()

    def log_message(self, *args):
        pass


class Mixed(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        connection_id = str(uuid4())
        try:
            with self.request.makefile("rb") as stream:
                line = stream.readline(8192).decode("ascii")
                method, authority, _ = line.split()
                host, port = authority.rsplit(":", 1)
                if method != "CONNECT" or host not in ("localhost", "127.0.0.1"):
                    return
                while stream.readline(8192) not in (b"\r\n", b"\n", b""):
                    pass
            release = threading.Event()
            row = {"id": connection_id, "start": datetime.now(timezone.utc).isoformat(),
                "chains": ["NODE", "PROBE"], "rule": "Match", "rulePayload": "",
                "metadata": {"network": "tcp", "type": "HTTPS", "host": "" if host == "127.0.0.1" else host,
                        "destinationIP": "127.0.0.1" if host == "127.0.0.1" else "",
                    "destinationPort": port, "sourceIP": self.client_address[0],
                    "sourcePort": str(self.client_address[1]), "inboundIP": "127.0.0.1",
                    "inboundPort": str(config["mixed-port"])}}
            if host == "127.0.0.1" and os.environ.get("NODELAB_FIXTURE_DIRECT") == "1":
                row["chains"] = ["DIRECT"]
            with lock:
                active[connection_id] = row, release
            self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            with ctx.wrap_socket(self.request, server_side=True) as secure:
                with secure.makefile("rb") as stream:
                    stream.readline(8192)
                    while stream.readline(8192) not in (b"\r\n", b"\n", b""):
                        pass
                    body = b'{"ip":"192.0.2.7"}' if host == "localhost" else b"ip=192.0.2.7\n"
                    secure.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode())
                    if not release.wait(10):
                        return
                    secure.sendall(body)
                    secure.recv(1)
        except (OSError, ValueError):
            pass
        finally:
            with lock:
                active.pop(connection_id, None)


class MixedServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


controller_port = int(config["external-controller"].rsplit(":", 1)[1])
controller = ThreadingHTTPServer(("127.0.0.1", controller_port), Controller)
mixed = MixedServer(("127.0.0.1", config["mixed-port"]), Mixed)
for server in (controller, mixed):
    threading.Thread(target=server.serve_forever, daemon=True).start()
threading.Event().wait()
