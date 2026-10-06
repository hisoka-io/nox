#!/usr/bin/env python3
"""Stand-in for the node's loopback ingress behind nox-kps.

GET answers "ok". POST /api/v1/responses/claim answers with encrypted-size
replies (32,296 bytes each); POST /api/v1/packets answers 202 like the node.

Reply modes:
  json     two replies (data + parity) as v1 JSON number arrays (~230 KB)
  binary   two replies as the claim v2 binary batch (64,797 bytes)
  binary1  one reply as the claim v2 binary batch (32,402 bytes), the
           common case when a long-poll claim returns the first reply

Usage: mock_upstream.py --port PORT --reply MODE [--delay-ms MS]
"""
import argparse
import json
import struct
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPLY = bytes((i * 131 + 7) % 256 for i in range(32296))


def claim_body(mode):
    ids = ["reply-0-%032x" % 1, "reply-0-%032x" % 2]
    if mode == "json":
        body = json.dumps([{"id": i, "data": list(REPLY)} for i in ids], separators=(",", ":"))
        return body.encode(), "application/json"
    if mode == "binary1":
        ids = ids[:1]
    out = bytearray([1]) + struct.pack(">H", len(ids))
    for i in ids:
        out += bytes([0]) + struct.pack(">H", len(i)) + i.encode() + struct.pack(">I", len(REPLY)) + REPLY
    return bytes(out), "application/vnd.nox.claim-batch"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--reply", choices=["json", "binary", "binary1"], default="binary")
    p.add_argument("--delay-ms", type=float, default=0.0, help="added before every answer")
    a = p.parse_args()
    body, ctype = claim_body(a.reply)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def send(self, code, ctype, payload):
            if a.delay_ms:
                time.sleep(a.delay_ms / 1000)
            self.send_response(code)
            self.send_header("content-type", ctype)
            self.send_header("content-length", str(len(payload)))
            self.send_header("x-nox-claim-version", "2")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            self.send(200, "text/plain", b"ok")

        def do_POST(self):
            self.rfile.read(int(self.headers.get("content-length", "0")))
            if self.path == "/api/v1/responses/claim":
                self.send(200, ctype, body)
            else:
                self.send(202, "text/plain", b"accepted")

    print(f"mock upstream :{a.port} reply {a.reply} claim body {len(body)} bytes", flush=True)
    ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
