"""httpd run as a single process (-X) stopped (SIGTERM) with a proxied
request suspended: the process destroys its pools on exit, including the
worker's connection pool, so a backend connection held by the suspended
request must have been given back by then (a clean exit, and no assertion in
the pool's cleanup).

usage: MODES="sync async" RUNS=10 python3 -I async-exit-check.py HTTPD_PREFIX WORKDIR
"""

import os
import socket
import subprocess
import threading
import time

here = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(here, "async-proto-check.py")).read().split("\nreport = []")[0])

# the clients going away with their requests in flight is what is checked
backend.handle_error = lambda *args: None


def start_single(async_conf):
    """httpd -X, started once it answers"""
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(CONF.format(prefix=prefix, work=work, front=FRONT, backend=BACKEND,
                            asyncconf=async_conf, passopts=""))
    for name in ("error_log", "access_log"):
        open(os.path.join(work, name), "w").close()
    p = subprocess.Popen([os.path.join(prefix, "bin", "httpd"), "-X", "-f",
                          os.path.join(work, "httpd.conf")],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for _ in range(100):
        try:
            get("/nothing", timeout=1)
            return p
        except OSError:
            time.sleep(0.05)
    stop(p)
    raise SystemExit("httpd -X didn't start")


def request_in_flight():
    """A request answered (so that the connection is established), then a
    slow one, left unanswered."""
    s = socket.create_connection(("127.0.0.1", FRONT), timeout=10)
    s.sendall(b"GET /slow?d=0 HTTP/1.1\r\nHost: x\r\n\r\n")
    data = b""
    while b"slow" not in data:
        data += s.recv(4096)
    s.sendall(b"GET /slow?d=1.5 HTTP/1.1\r\nHost: x\r\n\r\n")
    return s


report = []
MODES = {"sync": "ProxyAsyncDelay -1", "async": "ProxyAsyncDelay 0\n    ProxyAsyncIdleTimeout 10"}
runs = int(os.environ.get("RUNS", "10"))
for mode in os.environ.get("MODES", "sync async").split():
    bad = 0
    for i in range(runs):
        p = start_single(MODES[mode])
        try:
            s = request_in_flight()
            time.sleep(0.3)
            p.terminate()
            try:
                out = p.communicate(timeout=20)[0].decode(errors="replace")
                rc = p.returncode
            except subprocess.TimeoutExpired:
                stop(p)
                out, rc = "", "HUNG"
            s.close()
        finally:
            if p.poll() is None:
                stop(p)
        with open(os.path.join(work, "error_log"), errors="replace") as f:
            log = f.read()
        assertion = "ntotal" in log or "ntotal" in out or "Assertion" in out
        if rc != 0 or assertion:
            bad += 1
            report.append("%s run %d: FAIL exit status %s, assertion %s" % (mode, i, rc, assertion))
            report.append("   " + (out.strip().splitlines() or [""])[-1])
    report.append("%s: %d runs, %d unclean exits%s" % (mode, runs, bad, " FAIL" if bad else ""))
backend.shutdown()
print("\n".join(report))
