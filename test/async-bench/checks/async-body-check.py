"""Check the async response body streaming of the prototype (mod_proxy_http
waiting for the backend or the client without holding a worker).

usage: MODES="sync async" python3 -I async-body-check.py HTTPD_PREFIX WORKDIR
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
# the setup (Slow backend, conf, start/stop, get), not its report loop
exec(src.split("report = []")[0])


def chunks_GET(self):
    q = parse_qs(urlparse(self.path).query)
    path = urlparse(self.path).path
    if path.endswith("/chunks"):
        n, gap, size = int(q["n"][0]), float(q["gap"][0]), int(q["size"][0])
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for i in range(n):
            data = (b"%d" % i) * size
            self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
            self.wfile.flush()
            time.sleep(gap)
        self.wfile.write(b"0\r\n\r\n")
    elif path.endswith("/big"):
        size = int(q["size"][0])
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.end_headers()
        block = b"x" * 65536
        left = size
        while left > 0:
            n = min(left, len(block))
            self.wfile.write(block[:n])
            left -= n
    elif path.endswith("/stall"):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "100000")
        self.end_headers()
        self.wfile.write(b"y" * 1000)
        self.wfile.flush()
        time.sleep(float(q["t"][0]))
    else:
        Slow.do_GET_orig(self)


Slow.do_GET_orig = Slow.do_GET
Slow.do_GET = chunks_GET


def concurrent_chunks(n):
    results = [None] * n

    def one(i):
        results[i] = get("/slow/chunks?n=5&gap=0.3&size=1000&i=%d" % i, timeout=30)
    t0 = time.monotonic()
    ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    expect = b"".join((b"%d" % i) * 1000 for i in range(5))
    ok = all(r and r[0] == 200 and r[1] == expect for r in results)
    return time.monotonic() - t0, ok


def slow_reader(size, out):
    # The receive buffer set before connecting: shrunk below the window
    # advertised already, FreeBSD's TCP stalls
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
    s.settimeout(60)
    s.connect(("127.0.0.1", FRONT))
    s.sendall(b"GET /slow/big?size=%d HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" % size)
    data = b""
    t0 = time.monotonic()
    while True:
        b = s.recv(16384)
        if not b:
            break
        data += b
        time.sleep(0.002)  # a slow client
    s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    out["status"] = head.split(b" ")[1] if head else None
    out["len"] = len(body)
    out["time"] = time.monotonic() - t0


def stalled():
    s = socket.create_connection(("127.0.0.1", FRONT), timeout=20)
    s.sendall(b"GET /slow/stall?t=5 HTTP/1.1\r\nHost: x\r\n\r\n")
    data = b""
    t0 = time.monotonic()
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            data += b
    except (socket.timeout, ConnectionResetError) as e:
        data += b"[%s]" % type(e).__name__.encode()
    s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    return head.split(b" ")[1] if head else None, len(body), round(time.monotonic() - t0, 1)


report = []
MODES = {"sync": "ProxyAsyncDelay -1", "async": "ProxyAsyncDelay 0\n    ProxyAsyncIdleTimeout 2"}
for mode in os.environ.get("MODES", "sync async").split():
    p = start(MODES[mode])
    try:
        elapsed, ok = concurrent_chunks(10)
        report.append("%s: 10 concurrent chunked bodies (5 x 0.3s), 2 workers: %.2fs, all ok: %s"
                      % (mode, elapsed, ok))
        out = {}
        t = threading.Thread(target=slow_reader, args=(4 * 1024 * 1024, out))
        t.start()
        time.sleep(0.3)
        t0 = time.monotonic()
        fast = [get("/slow?d=0&f=%d" % i, timeout=30)[0] for i in range(6)]
        fast_time = time.monotonic() - t0
        t.join()
        report.append("%s: slow client 4MB: status %s, %s bytes, %.1fs; 6 fast requests meanwhile: %s in %.2fs"
                      % (mode, out.get("status"), out.get("len"), out.get("time", 0), fast, fast_time))
        outs = [{}, {}]
        ts = [threading.Thread(target=slow_reader, args=(1024 * 1024, o)) for o in outs]
        for t in ts:
            t.start()
        time.sleep(0.3)
        t0 = time.monotonic()
        fast = [get("/slow?d=0&g=%d" % i, timeout=120)[0] for i in range(6)]
        fast_time = time.monotonic() - t0
        for t in ts:
            t.join()
        report.append("%s: 2 slow clients 1MB (all workers): %s; 6 fast requests meanwhile: %s in %.2fs"
                      % (mode, [(o.get("status"), o.get("len"), round(o.get("time", 0), 1)) for o in outs],
                         fast, fast_time))
        if mode == "async":
            report.append("async: backend stalls mid-body 5s > ProxyAsyncIdleTimeout 2s: "
                          "(status, body bytes, seconds) = %s" % (stalled(),))
            c = http.client.HTTPConnection("127.0.0.1", FRONT, timeout=20)
            seq = [get("/slow/chunks?n=2&gap=0.1&size=10&k=%d" % i, conn=c)[0] for i in range(3)]
            c.close()
            report.append("async: keepalive after chunked bodies: %s" % seq)
        report.append("%s: error_log: %s" % (mode, log_findings()))
    finally:
        report.append("%s: %s" % (mode, stop(p)))
backend.shutdown()
print("\n".join(report))
