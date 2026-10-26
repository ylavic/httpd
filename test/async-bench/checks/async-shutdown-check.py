"""Graceful restart/stop and hard restart/stop of httpd with requests
suspended in various phases (response wait, body streaming, waiting for the
client's body, connect in progress).

usage: python3 -I async-shutdown-check.py HTTPD_PREFIX WORKDIR
"""

import hashlib
import os
import signal
import socket
import subprocess
import threading
import time

here = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(here, "async-body-check.py")).read().split("\nreport = []")[0])

CONF = CONF.replace("ServerLimit 1", "ServerLimit 2").replace(
    "MaxRequestWorkers 2", "MaxRequestWorkers 4").replace(
    "MaxSpareThreads 2", "MaxSpareThreads 4")
CONF += """
<Location "/blackhole">
    ProxyPass "http://192.0.2.1:18431/blackhole" connectiontimeout=3 retry=1ms
    {asyncconf}
</Location>
"""


def echo_POST(self):
    n = int(self.headers.get("Content-Length", "0"))
    data = self.rfile.read(n)
    body = ("%d %s\n" % (len(data), hashlib.sha256(data).hexdigest()[:16])).encode()
    self.send_response(200)
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)


Slow.do_POST = echo_POST


def http_req(raw_req, parts=(), gap=0, timeout=20):
    """Send a request (and slow body parts), return (status, body, seconds)
    or the error (e.g. 'closed' when the connection is closed without a
    response)."""
    t0 = time.monotonic()
    try:
        s = socket.create_connection(("127.0.0.1", FRONT), timeout=timeout)
        s.sendall(raw_req)
        for p in parts:
            time.sleep(gap)
            s.sendall(p)
        data = b""
        while True:
            b = s.recv(65536)
            if not b:
                break
            data += b
            head, sep, body = data.partition(b"\r\n\r\n")
            if sep and b"chunked" in head.lower() and body.endswith(b"0\r\n\r\n"):
                break
            if sep and b"content-length:" in head.lower():
                cl = int([l for l in head.split(b"\r\n")
                          if l.lower().startswith(b"content-length:")][0].split(b":")[1])
                if len(body) >= cl:
                    break
        s.close()
    except (OSError, socket.timeout) as e:
        return (type(e).__name__, b"", round(time.monotonic() - t0, 1))
    if not data:
        return ("closed", b"", round(time.monotonic() - t0, 1))
    head, _, body = data.partition(b"\r\n\r\n")
    return (head.split(b" ")[1].decode(), body, round(time.monotonic() - t0, 1))


def in_flight():
    """Start the requests, return (threads, results)"""
    up = b"u" * 1000
    reqs = {
        "response 3s #1": ((b"GET /slow?d=%s&a=1" % os.environ.get("RESPDELAY", "3").encode()) + b" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",),
        "response 3s #2": ((b"GET /slow?d=%s&a=2" % os.environ.get("RESPDELAY", "3").encode()) + b" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",),
        "response 3s #3": ((b"GET /slow?d=%s&a=3" % os.environ.get("RESPDELAY", "3").encode()) + b" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",),
        "body 5x0.6s #1": (b"GET /slow/chunks?n=5&gap=0.6&size=100&b=1 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",),
        "body 5x0.6s #2": (b"GET /slow/chunks?n=5&gap=0.6&size=100&b=2 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",),
        "upload 5x0.6s #1": (b"POST /slow/up?c=1 HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 5000\r\n\r\n", [up] * 5, 0.6),
        "upload 5x0.6s #2": (b"POST /slow/up?c=2 HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 5000\r\n\r\n", [up] * 5, 0.6),
        "connect 3s": (b"GET /blackhole HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",),
    }
    res = {}

    def one(name, args):
        res[name] = http_req(*args)
    th = [threading.Thread(target=one, args=(k, v)) for k, v in reqs.items()]
    for t in th:
        t.start()
    return th, res


def children(pid):
    return subprocess.run(["pgrep", "-P", str(pid)], capture_output=True,
                          text=True).stdout.split()


report = []
ASYNC = os.environ.get("ASYNCCONF", "ProxyAsyncDelay 0\n    ProxyAsyncIdleTimeout 10")
BASE_CONF = CONF
SCENARIOS = (("graceful restart", signal.SIGUSR1, False, ""),
             ("graceful stop", signal.SIGWINCH, True, ""),
             ("graceful stop, GracefulShutdownTimeout 2", signal.SIGWINCH, True,
              "GracefulShutdownTimeout 2\n"),
             ("restart", signal.SIGHUP, False, ""),
             ("stop", signal.SIGTERM, True, ""))
only = os.environ.get("ONLY")
for name, sig, stops, extra in SCENARIOS:
    if only and only not in name:
        continue
    CONF = BASE_CONF + extra
    p = start(ASYNC)
    if p.poll() is not None or not children(p.pid):
        if p.poll() is None:
            stop(p)
        raise SystemExit("%s: our httpd isn't the one running (leftover?)" % name)
    try:
        th, res = in_flight()
        time.sleep(0.8)
        old = children(p.pid)
        t0 = time.monotonic()
        os.kill(p.pid, sig)
        for t in th:
            t.join(30)
        if stops:
            try:
                p.wait(30)
                exited = "exited after %.1fs" % (time.monotonic() - t0)
            except subprocess.TimeoutExpired:
                exited = "STILL RUNNING after 30s"
        else:
            time.sleep(0.5)
            try:
                st = get("/slow?d=0&after=1", timeout=10)[0]
            except Exception as e:
                st = type(e).__name__
            for _ in range(150):
                left = [c for c in old if c in children(p.pid)]
                if not left:
                    break
                time.sleep(0.1)
            exited = "serving after: %s, old children left: %s (%.1fs after the signal)" % (
                st, left, time.monotonic() - t0)
        report.append("== %s: %s" % (name, exited))
        for k in sorted(res):
            st, body, secs = res[k]
            report.append("   %-17s %s after %ss, %d body bytes" % (k, st, secs, len(body)))
        with open(os.path.join(work, "error_log")) as f:
            log = f.read()
        report.append("   error_log: crashes %d, abandoned %d, wait errors %d" % (
            log.count("exit signal"), log.count("abandoned by its continuation"),
            log.count("can't wait")))
    finally:
        if p.poll() is None:
            stop(p)
backend.shutdown()
print("\n".join(report))
