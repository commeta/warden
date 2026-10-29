"""A small HTTP client with source-address selection, usable from a namespace.

Both the attack generator and the pytest ``attacker``/``client`` fixtures need
to send a request *from a chosen IP* — an address out of the attacker's whole
range (``IP_FREEBIND``), a specific /64 host, or the trusted client address —
and sometimes raw bytes. In ``netns`` mode the caller runs this inside the
namespace with ``ip netns exec``; the logic is identical either way.

Run directly for one request and JSON output:

    python3 httpcli.py --src 198.18.0.7 --host wordpress.lab.local \
        --url http://10.77.0.1/index.php?q=x
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
from dataclasses import dataclass, field

IP_FREEBIND = 15  # <linux/in.h> IP_FREEBIND


@dataclass
class Response:
    status: int
    body: str
    headers: dict = field(default_factory=dict)
    error: str = ""


def _connect(host: str, port: int, src: str | None, timeout: float) -> socket.socket:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(timeout)
    if src:
        sfamily = socket.AF_INET6 if ":" in src else socket.AF_INET
        if sfamily != family:
            # connecting to v4 target from a v6 source makes no sense; let the
            # caller pick a matching target address
            pass
        lvl = socket.IPPROTO_IPV6 if sfamily == socket.AF_INET6 else socket.IPPROTO_IP
        opt = 79 if sfamily == socket.AF_INET6 else IP_FREEBIND  # IPV6_FREEBIND=78? use 79 fallback
        try:
            s.setsockopt(socket.IPPROTO_IP if sfamily == socket.AF_INET else lvl,
                         IP_FREEBIND if sfamily == socket.AF_INET else opt, 1)
        except OSError:
            pass
        try:
            s.bind((src, 0))
        except OSError as e:
            s.close()
            raise OSError(f"bind {src}: {e}") from e
    s.connect((host, port))
    return s


def request(
    method: str,
    host: str,
    port: int,
    path: str,
    *,
    src: str | None = None,
    http_host: str | None = None,
    tls: bool = False,
    body: bytes | None = None,
    headers: dict | None = None,
    timeout: float = 5.0,
) -> Response:
    try:
        sock = _connect(host, port, src, timeout)
    except OSError as e:
        return Response(0, "", error=str(e))
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=http_host or host)
        hdrs = {
            "Host": http_host or host,
            "User-Agent": "warden-lab/2.0",
            "Connection": "close",
            "Accept": "*/*",
        }
        if headers:
            hdrs.update(headers)
        if body is not None:
            hdrs.setdefault("Content-Length", str(len(body)))
        req = f"{method} {path} HTTP/1.1\r\n"
        req += "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
        req += "\r\n"
        data = req.encode() + (body or b"")
        sock.sendall(data)
        chunks = []
        while True:
            try:
                b = sock.recv(65536)
            except (TimeoutError, OSError):
                break
            if not b:
                break
            chunks.append(b)
        raw = b"".join(chunks)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return _parse(raw)


def request_raw(host: str, port: int, raw: bytes, *, src: str | None = None, tls: bool = False, timeout: float = 5.0) -> Response:
    """Send exactly these bytes (for malformed-request / forgery tests)."""
    try:
        sock = _connect(host, port, src, timeout)
    except OSError as e:
        return Response(0, "", error=str(e))
    try:
        if tls:
            ctx = ssl._create_unverified_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(raw)
        chunks = []
        while True:
            try:
                b = sock.recv(65536)
            except (TimeoutError, OSError):
                break
            if not b:
                break
            chunks.append(b)
        return _parse(b"".join(chunks))
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _parse(raw: bytes) -> Response:
    if not raw:
        return Response(0, "", error="no response")
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        return Response(0, "", error="bad status line")
    headers = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(b":")
        headers[k.decode(errors="replace").strip().lower()] = v.decode(errors="replace").strip()
    return Response(status, body.decode("utf-8", "replace"), headers)


def _split_url(url: str) -> tuple[bool, str, int, str]:
    tls = url.startswith("https://")
    rest = url.split("://", 1)[1]
    hostport, _, path = rest.partition("/")
    path = "/" + path
    if hostport.startswith("["):
        host, _, pp = hostport[1:].partition("]")
        port = int(pp.lstrip(":")) if pp.lstrip(":") else (443 if tls else 80)
    else:
        host, _, pp = hostport.partition(":")
        port = int(pp) if pp else (443 if tls else 80)
    return tls, host, port, path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="one HTTP request from a chosen source")
    ap.add_argument("--src")
    ap.add_argument("--host", dest="http_host")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--url", required=True)
    ap.add_argument("--data")
    ap.add_argument("--count", type=int, default=1)
    args = ap.parse_args(argv)
    tls, host, port, path = _split_url(args.url)
    codes: dict[int, int] = {}
    last = None
    for _ in range(args.count):
        r = request(args.method, host, port, path, src=args.src, http_host=args.http_host,
                    tls=tls, body=args.data.encode() if args.data else None)
        codes[r.status] = codes.get(r.status, 0) + 1
        last = r
    json.dump({"codes": codes, "error": (last.error if last else ""), "body_head": (last.body[:200] if last else "")}, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
