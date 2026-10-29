#!/usr/bin/env python3
"""Warden Lab microservice — Python, single asyncio event loop (ASGI-style).

Stdlib only (asyncio). Models the "one process, event loop" shape; swap in
FastAPI+uvicorn on a real deployment — the contract is identical.
"""
import asyncio
import os
import re
import sqlite3
import subprocess
import urllib.parse

ROOT = os.environ.get("LAB_ROOT", "/tmp")
PORT = int(os.environ.get("PORT", "3102"))
DB = os.path.join(ROOT, "data", "items.sqlite")
UPLOADS = os.path.join(ROOT, "uploads")


def item(id_: str) -> str:
    try:
        con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
        # interpolated on purpose (a SQLi target); the connection is read-only
        rows = con.execute(f"SELECT id,name,note FROM items WHERE id = {id_}").fetchall()
        con.close()
        return "\n".join("|".join(map(str, r)) for r in rows) or "no result"
    except Exception:
        return "error"


async def handle(reader, writer):
    try:
        line = await asyncio.wait_for(reader.readline(), 5)
        parts = line.decode("latin1").split()
        if len(parts) < 2:
            writer.close(); return
        method, target = parts[0], parts[1]
        headers = {}
        clen = 0
        while True:
            h = await asyncio.wait_for(reader.readline(), 5)
            if h in (b"\r\n", b"", b"\n"):
                break
            k, _, v = h.decode("latin1").partition(":")
            headers[k.strip().lower()] = v.strip()
        if headers.get("content-length"):
            clen = min(int(headers["content-length"]), 262144)
        body = await reader.readexactly(clen) if clen else b""
        resp = route(method, target, body)
    except Exception:
        resp = (500, "error")
    code, text = resp
    out = (f"HTTP/1.1 {code} X\r\nContent-Type: text/plain; charset=utf-8\r\n"
           f"X-Lab-Service: python-asgi\r\nContent-Length: {len(text.encode())}\r\n"
           f"Connection: close\r\n\r\n{text}")
    writer.write(out.encode())
    await writer.drain()
    writer.close()


def route(method, target, body):
    u = urllib.parse.urlparse(target)
    path = re.sub(r"^/svc/[^/]+", "", u.path) or "/"
    q = urllib.parse.parse_qs(u.query)
    if path == "/health":
        return (200, "ok")
    if path == "/echo":
        return (200, "echo: " + (q.get("q", [""])[0]))
    if path == "/item":
        return (200, item(q.get("id", ["1"])[0]))
    if path == "/spawn":
        try:
            return (200, subprocess.run(["/usr/bin/id"], capture_output=True, text=True, timeout=2).stdout)
        except Exception:
            return (200, "spawned")
    if path == "/sleep":
        import time
        time.sleep(min(int(q.get("ms", ["0"])[0] or 0), 10000) / 1000)
        return (200, "slept")
    if path == "/alloc":
        mb = min(int(q.get("mb", ["1"])[0] or 1), 256)
        buf = bytearray(mb * 1024 * 1024)
        return (200, f"alloc {mb} ({buf[0]})")
    if path == "/upload" and method == "POST":
        os.makedirs(UPLOADS, exist_ok=True)
        name = re.sub(r"[^A-Za-z0-9._-]", "_", q.get("name", ["upload.bin"])[0])
        with open(os.path.join(UPLOADS, name), "wb") as f:
            f.write(body)
        return (200, f"stored uploads/{name}")
    return (404, "not found")


async def main():
    srv = await asyncio.start_server(handle, "127.0.0.1", PORT)
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
