"""Check the async request sending of the prototype (mod_proxy_http waiting
for the client's upload or the backend without holding a worker).

usage: MODES="sync async" python3 -I async-send-check.py HTTPD_PREFIX WORKDIR
"""

import hashlib
import http.client
import os
import socket
import sys
import threading
import time
from urllib.parse import parse_qs, urlparse

here = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(here, "async-proto-check.py")).read()
src = src.replace("KeepAliveTimeout 5", "KeepAliveTimeout 5\nTimeout 3")
exec(src.split("report = []")[0])


def do_POST(self):
    q = parse_qs(urlparse(self.path).query)
    left = int(self.headers.get("Content-Length", "0"))
    gap = float(q.get("r", ["0"])[0])
    h = hashlib.sha256()
    n = 0
    while left > 0:
        b = self.rfile.read(min(left, 65536))
        if not b:
            break
        h.update(b)
        n += len(b)
        left -= len(b)
        if gap:
            time.sleep(gap)
    body = ("%d %s\n" % (n, h.hexdigest()[:16])).encode()
    self.send_response(200)
    self.send_header("Content-Type", "text/plain")
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)


Slow.do_POST = do_POST


def raw(req_head, parts, gap, timeout=30):
    s = socket.create_connection(("127.0.0.1", FRONT), timeout=timeout)
    s.sendall(req_head)
    for p in parts:
        time.sleep(gap)
        s.sendall(p)
    data = b""
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            data += b
            if b"\r\n\r\n" in data:
                head, _, body = data.partition(b"\r\n\r\n")
                cl = [l for l in head.split(b"\r\n") if l.lower().startswith(b"content-length:")]
                if cl and len(body) >= int(cl[0].split(b":")[1]):
                    break
    except (socket.timeout, ConnectionResetError):
        pass
    s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    return (head.split(b" ")[1] if head else None), body


def slow_upload(i, n, size, gap):
    parts = [bytes([65 + (k % 26)]) * size for k in range(n)]
    total = b"".join(parts)
    head = (b"POST /slow/up?i=%d HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
            b"Content-Length: %d\r\n\r\n" % (i, len(total)))
    status, body = raw(head, parts, gap)
    expect = ("%d %s\n" % (len(total), hashlib.sha256(total).hexdigest()[:16])).encode()
    return status == b"200" and body == expect


def concurrent_uploads(k):
    results = [None] * k

    def one(i):
        results[i] = slow_upload(i, 5, 1000, 0.3)
    t0 = time.monotonic()
    ts = [threading.Thread(target=one, args=(i,)) for i in range(k)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return time.monotonic() - t0, all(results)


def big_upload_slow_backend(out):
    data = os.urandom(1024 * 1024) * 8
    t0 = time.monotonic()
    c = http.client.HTTPConnection("127.0.0.1", FRONT, timeout=120)
    c.request("POST", "/slow/up?r=0.02", body=data,
              headers={"Content-Type": "application/octet-stream"})
    r = c.getresponse()
    body = r.read()
    c.close()
    out["ok"] = (r.status == 200 and
                 body == ("%d %s\n" % (len(data), hashlib.sha256(data).hexdigest()[:16])).encode())
    out["time"] = time.monotonic() - t0


report = []
MODES = {"sync": "ProxyAsyncDelay -1", "async": "ProxyAsyncDelay 0\n    ProxyAsyncIdleTimeout 5"}
for mode in os.environ.get("MODES", "sync async").split():
    p = start(MODES[mode])
    try:
        elapsed, ok = concurrent_uploads(10)
        report.append("%s: 10 concurrent slow uploads (5 x 1000B, 0.3s apart), 2 workers: %.2fs, all ok: %s"
                      % (mode, elapsed, ok))
        ups = []
        uts = [threading.Thread(target=lambda i=i: ups.append(slow_upload(100 + i, 5, 1000, 0.3)))
               for i in range(4)]
        for t in uts:
            t.start()
        time.sleep(0.2)
        t0 = time.monotonic()
        fast = [get("/slow?d=0&u=%d" % i, timeout=60)[0] for i in range(6)]
        fast_time = time.monotonic() - t0
        for t in uts:
            t.join()
        report.append("%s: 4 slow uploads (all workers busy), 6 fast GETs meanwhile: %s in %.2fs, uploads ok: %s"
                      % (mode, fast, fast_time, all(ups) and len(ups) == 4))
        out = {}
        t = threading.Thread(target=big_upload_slow_backend, args=(out,))
        t.start()
        time.sleep(0.5)
        t0 = time.monotonic()
        fast = [get("/slow?d=0&f=%d" % i, timeout=60)[0] for i in range(6)]
        fast_time = time.monotonic() - t0
        t.join()
        report.append("%s: 8MB upload to a slow-reading backend: ok %s in %.1fs; 6 fast requests meanwhile: %s in %.2fs"
                      % (mode, out.get("ok"), out.get("time", 0), fast, fast_time))
        if mode == "async":
            t0 = time.monotonic()
            status, _ = raw(b"POST /slow/up HTTP/1.1\r\nHost: x\r\nContent-Length: 2000\r\n\r\n",
                            [b"z" * 1000], 0.1, timeout=15)
            report.append("async: upload stalls half way, Timeout 3s: %s after %.1fs"
                          % (status, time.monotonic() - t0))
            c = http.client.HTTPConnection("127.0.0.1", FRONT, timeout=20)
            c.request("POST", "/slow/up?k=1", body=b"hello")
            r1 = c.getresponse()
            b1 = r1.read()
            c.request("GET", "/slow?d=0&k=2")
            r2 = c.getresponse()
            r2.read()
            c.close()
            report.append("async: keepalive POST then GET: %s %s (%s)" % (r1.status, r2.status, b1.strip()))
        report.append("%s: error_log: %s" % (mode, log_findings()))
    finally:
        report.append("%s: %s" % (mode, stop(p)))
backend.shutdown()
print("\n".join(report))
