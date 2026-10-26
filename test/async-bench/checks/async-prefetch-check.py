"""Check the request body prefetch (and spool) of the prototype waiting for
the client without holding a worker.

usage: MODES="sync async" python3 -I async-prefetch-check.py HTTPD_PREFIX WORKDIR
"""

import hashlib
import os
import threading
import time

here = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(here, "async-send-check.py")).read().split("\nreport = []")[0])

CONF = CONF.replace("LoadModule proxy_module",
                    "LoadModule env_module modules/mod_env.so\nLoadModule proxy_module")
CONF += """
<Location "/spool">
    ProxyPass "http://127.0.0.1:{backend}/slow"
    SetEnv proxy-sendcl 1
    {asyncconf}
</Location>
"""


def read_chunked(rfile):
    out = b""
    while True:
        size = int(rfile.readline().split(b";")[0], 16)
        if not size:
            while rfile.readline() not in (b"\r\n", b"\n", b""):
                pass
            return out
        out += rfile.read(size)
        rfile.readline()


def echo_POST(self):
    """Answers how the body came (cl=N or chunked) with its length/digest"""
    if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
        how, data = "chunked", read_chunked(self.rfile)
    else:
        n = int(self.headers.get("Content-Length", "0"))
        how, data = "cl=%d" % n, self.rfile.read(n)
    body = ("%s %d %s\n" % (how, len(data), hashlib.sha256(data).hexdigest()[:16])).encode()
    self.send_response(200)
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)


Slow.do_POST = echo_POST


def upload(path, n, size, gap, chunked, res, i, t0):
    parts = [bytes([65 + (k % 26)]) * size for k in range(n)]
    total = b"".join(parts)
    head = b"POST %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n" % path.encode()
    if chunked:
        head += b"Transfer-Encoding: chunked\r\n\r\n"
        parts = [b"%x\r\n%s\r\n" % (len(p), p) for p in parts] + [b"0\r\n\r\n"]
    else:
        head += b"Content-Length: %d\r\n\r\n" % len(total)
    status, body = raw(head, parts, gap)
    digest = "%d %s" % (len(total), hashlib.sha256(total).hexdigest()[:16])
    how = body.split(b" ")[0].decode() if body else None
    res[i] = (status, how, body.decode().strip().endswith(digest),
              round(time.monotonic() - t0, 2))


def with_fast(uploads):
    """Run the uploads, and 6 fast GETs 0.3s in; their max latency"""
    res = [None] * len(uploads)
    t0 = time.monotonic()
    th = [threading.Thread(target=upload, args=u + (res, i, t0))
          for i, u in enumerate(uploads)]
    for t in th:
        t.start()
    time.sleep(0.3)
    fast = []

    def one():
        t = time.monotonic()
        st = get("/slow?d=0", timeout=30)[0]
        fast.append((st, time.monotonic() - t))
    th2 = [threading.Thread(target=one) for _ in range(6)]
    for t in th2:
        t.start()
    for t in th + th2:
        t.join()
    return res, max(t for s, t in fast), sorted(set(s for s, t in fast))


report = []
MODES = {"sync": "ProxyAsyncDelay -1", "async": "ProxyAsyncDelay 0\n    ProxyAsyncIdleTimeout 2"}
for mode in os.environ.get("MODES", "sync async").split():
    p = start(MODES[mode])
    try:
        # small bodies (5 x 200B, 0.3s apart): within the prefetch (16K)
        for chunked in (0, 1):
            res, fmax, fst = with_fast([("/slow/pf?c=%d" % chunked, 5, 200, 0.3, chunked)] * 4)
            report.append("%s: 4 slow small %s uploads: %s; 6 fast GETs max %.2fs %s"
                          % (mode, "chunked" if chunked else "C-L", res, fmax, fst))
        # large chunked bodies spooled (proxy-sendcl): 5 x 20K, 0.3s apart
        res, fmax, fst = with_fast([("/spool/sp", 5, 20000, 0.3, 1)] * 4)
        report.append("%s: 4 slow large chunked uploads, proxy-sendcl: %s; 6 fast GETs max %.2fs %s"
                      % (mode, res, fmax, fst))
        # a large chunked body streamed (no proxy-sendcl): 5 x 20K
        res, fmax, fst = with_fast([("/slow/st", 5, 20000, 0.3, 1)] * 2)
        report.append("%s: 2 slow large chunked uploads, streamed: %s; fast max %.2fs"
                      % (mode, res, fmax))
        if mode == "async":
            # stalls (Timeout 3): while prefetching, and while spooling
            t0 = time.monotonic()
            st, _ = raw(b"POST /slow/x HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n",
                        [b"x" * 100], 0)
            report.append("async: prefetch stalls (100/1000B, Timeout 3s): %s after %.1fs"
                          % (st, time.monotonic() - t0))
            t0 = time.monotonic()
            st, _ = raw(b"POST /spool/x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n",
                        [b"4e20\r\n" + b"y" * 20000 + b"\r\n"], 0)
            report.append("async: spool stalls (20K then nothing): %s after %.1fs"
                          % (st, time.monotonic() - t0))
        with open(os.path.join(work, "error_log")) as f:
            log = f.read()
        report.append("%s: waits: prefetching %d, spooling %d, timeouts %d, crashes %d"
                      % (mode, log.count("prefetching the request body: waiting"),
                         log.count("spooling the request body: waiting"),
                         log.count("timeout waiting for the client while"),
                         log.count("exit signal")))
    finally:
        report.append("%s: %s" % (mode, stop(p)))
backend.shutdown()
print("\n".join(report))
