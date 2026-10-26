"""Check the nonblocking response head reading of the prototype.

usage: MODES="sync async" python3 -I async-head-check.py HTTPD_PREFIX WORKDIR
"""

import http.client
import os
import socket
import sys
import threading
import time
from urllib.parse import parse_qs, urlparse

here = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(here, "async-proto-check.py")).read()
exec(src.split("report = []")[0])


def head_GET(self):
    q = parse_qs(urlparse(self.path).query)
    path = urlparse(self.path).path
    w = self.wfile
    if path.endswith("/head"):
        n, gap = int(q["n"][0]), float(q["gap"][0])
        w.write(b"HTTP/1.1 200 OK\r\n")
        w.flush()
        for i in range(n):
            time.sleep(gap)
            w.write(b"X-Slow-%d: %d\r\n" % (i, i))
            w.flush()
        body = b"head done\n"
        w.write(b"Content-Length: %d\r\n\r\n%s" % (len(body), body))
    elif path.endswith("/early"):
        w.write(b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n")
        w.flush()
        time.sleep(0.3)
        body = b"after hints\n"
        w.write(b"HTTP/1.1 201 Created\r\nX-Final: yes\r\n"
                b"X-Folded: one\r\n two\r\n"
                b"X-Long: " + b"L" * 6000 + b"\r\n"
                b"Content-Length: %d\r\n\r\n%s" % (len(body), body))
    else:
        Slow.do_GET_orig(self)
    w.flush()


Slow.do_GET_orig = Slow.do_GET
Slow.do_GET = head_GET


def concurrent_heads(k):
    res = [None] * k

    def one(i):
        c = http.client.HTTPConnection("127.0.0.1", FRONT, timeout=30)
        c.request("GET", "/slow/head?n=5&gap=0.3&i=%d" % i)
        r = c.getresponse()
        res[i] = (r.status, r.getheader("X-Slow-4"), r.read())
        c.close()
    t0 = time.monotonic()
    ts = [threading.Thread(target=one, args=(i,)) for i in range(k)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    ok = all(r == (200, "4", b"head done\n") for r in res)
    return time.monotonic() - t0, ok, res if not ok else ""


def early():
    s = socket.create_connection(("127.0.0.1", FRONT), timeout=20)
    s.sendall(b"GET /slow/early HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    data = b""
    while True:
        b = s.recv(65536)
        if not b:
            break
        data += b
    s.close()
    heads = [h.split(b"\r\n")[0] for h in data.split(b"\r\n\r\n") if h.startswith(b"HTTP/")]
    return (heads, b"X-Final: yes" in data, b"X-Folded: one two" in data or b"X-Folded: one" in data,
            (b"L" * 6000) in data, data.endswith(b"after hints\n"))


report = []
MODES = {"sync": "ProxyAsyncDelay -1", "async": "ProxyAsyncDelay 0\n    ProxyAsyncIdleTimeout 5"}
for mode in os.environ.get("MODES", "sync async").split():
    p = start(MODES[mode])
    try:
        elapsed, ok, res = concurrent_heads(10)
        report.append("%s: 10 concurrent slow heads (5 headers 0.3s apart), 2 workers: %.2fs, all ok: %s %s"
                      % (mode, elapsed, ok, res))
        report.append("%s: 103 then 201 (heads, X-Final, X-Folded, X-Long, body): %s" % (mode, early(),))
        report.append("%s: error_log: %s" % (mode, log_findings()))
    finally:
        report.append("%s: %s" % (mode, stop(p)))
backend.shutdown()
print("\n".join(report))
