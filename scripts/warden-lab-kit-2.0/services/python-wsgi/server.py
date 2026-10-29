#!/usr/bin/env python3
"""Warden Lab microservice — Python, prefork workers (WSGI-style).

Stdlib only (http.server + a forking server), modelling the "several worker
processes" shape of Flask+gunicorn. Same contract as every other service.
"""
import os
import re
import sqlite3
import subprocess
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler
from socketserver import ForkingTCPServer

ROOT = os.environ.get("LAB_ROOT", "/tmp")
PORT = int(os.environ.get("PORT", "3103"))
DB = os.path.join(ROOT, "data", "items.sqlite")
UPLOADS = os.path.join(ROOT, "uploads")


def item(id_: str) -> str:
    try:
        con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
        rows = con.execute(f"SELECT id,name,note FROM items WHERE id = {id_}").fetchall()
        con.close()
        return "\n".join("|".join(map(str, r)) for r in rows) or "no result"
    except Exception:
        return "error"


class H(BaseHTTPRequestHandler):
    server_version = "warden-lab-wsgi"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # quiet
        pass

    def _reply(self, code, text):
        data = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("X-Lab-Service", "python-wsgi")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._route("GET", b"")

    def do_POST(self):
        n = min(int(self.headers.get("Content-Length", "0") or 0), 262144)
        self._route("POST", self.rfile.read(n))

    def _route(self, method, body):
        u = urllib.parse.urlparse(self.path)
        path = re.sub(r"^/svc/[^/]+", "", u.path) or "/"
        q = urllib.parse.parse_qs(u.query)
        if path == "/health":
            return self._reply(200, "ok")
        if path == "/echo":
            return self._reply(200, "echo: " + q.get("q", [""])[0])
        if path == "/item":
            return self._reply(200, item(q.get("id", ["1"])[0]))
        if path == "/spawn":
            try:
                return self._reply(200, subprocess.run(["/usr/bin/id"], capture_output=True, text=True, timeout=2).stdout)
            except Exception:
                return self._reply(200, "spawned")
        if path == "/sleep":
            time.sleep(min(int(q.get("ms", ["0"])[0] or 0), 10000) / 1000)
            return self._reply(200, "slept")
        if path == "/alloc":
            mb = min(int(q.get("mb", ["1"])[0] or 1), 256)
            buf = bytearray(mb * 1024 * 1024)
            return self._reply(200, f"alloc {mb} ({buf[0]})")
        if path == "/upload" and method == "POST":
            os.makedirs(UPLOADS, exist_ok=True)
            name = re.sub(r"[^A-Za-z0-9._-]", "_", q.get("name", ["upload.bin"])[0])
            with open(os.path.join(UPLOADS, name), "wb") as f:
                f.write(body)
            return self._reply(200, f"stored uploads/{name}")
        self._reply(404, "not found")


class Server(ForkingTCPServer):
    allow_reuse_address = True
    max_children = 6


if __name__ == "__main__":
    Server(("127.0.0.1", PORT), H).serve_forever()
