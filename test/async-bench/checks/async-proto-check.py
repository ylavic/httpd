"""Check the ap_mpm_register_wait() prototype: mod_proxy_http waiting for the
backend's response without holding a worker thread.

usage: python3 -I async-proto-check.py HTTPD_PREFIX WORKDIR
"""

import http.client
import os
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

prefix, work = sys.argv[1], sys.argv[2]
os.makedirs(work, exist_ok=True)
BACKEND, FRONT = 18431, 18432


class Slow(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        time.sleep(float(q.get("d", ["1"])[0]))
        body = ("slow %s\n" % self.path).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


backend = ThreadingHTTPServer(("127.0.0.1", BACKEND), Slow)
threading.Thread(target=backend.serve_forever, daemon=True).start()

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{front}
PidFile "{work}/httpd.pid"
ErrorLog "{work}/error_log"
LogLevel warn proxy_http:trace5 mpm_event:debug
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
ServerName localhost
StartServers 1
ServerLimit 1
ThreadLimit 2
ThreadsPerChild 2
MaxRequestWorkers 2
MinSpareThreads 1
MaxSpareThreads 2
KeepAliveTimeout 5
LogFormat "%r %>s %D" t
CustomLog "{work}/access_log" t
<Location "/slow">
    ProxyPass "http://127.0.0.1:{backend}/slow" {passopts}
    {asyncconf}
</Location>
<Location "/to">
    ProxyPass "http://127.0.0.1:{backend}/to" timeout=2 {passopts}
    {asyncconf}
</Location>
"""


def start(async_conf):
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(CONF.format(prefix=prefix, work=work, front=FRONT, backend=BACKEND,
                            asyncconf=async_conf, passopts=os.environ.get("PASSOPTS", "")))
    for name in ("error_log", "access_log"):
        open(os.path.join(work, name), "w").close()
    p = subprocess.Popen([os.path.join(prefix, "bin", "httpd"), "-f",
                          os.path.join(work, "httpd.conf"), "-DFOREGROUND"])
    for _ in range(100):
        try:
            c = http.client.HTTPConnection("127.0.0.1", FRONT, timeout=1)
            c.request("GET", "/nothing")
            c.getresponse().read()
            c.close()
            return p
        except OSError:
            time.sleep(0.05)
    stop(p)
    raise SystemExit("httpd didn't start")


def stop(p):
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
        return "stopped"
    except subprocess.TimeoutExpired:
        for kid in subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True,
                                  text=True).stdout.split():
            os.kill(int(kid), signal.SIGKILL)
        os.kill(p.pid, signal.SIGKILL)
        p.wait(10)
        return "STOP HUNG (killed)"


def get(path, conn=None, timeout=20):
    c = conn or http.client.HTTPConnection("127.0.0.1", FRONT, timeout=timeout)
    c.request("GET", path)
    r = c.getresponse()
    body = r.read()
    if not conn:
        c.close()
    return r.status, body


def concurrent(n, delay):
    results = [None] * n

    def one(i):
        results[i] = get("/slow?d=%s&i=%d" % (delay, i), timeout=15)
    t0 = time.monotonic()
    threads = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - t0
    ok = all(r and r[0] == 200 and (b"i=%d" % i) in r[1] for i, r in enumerate(results))
    return elapsed, ok, [r[0] if r else None for r in results]


def log_findings():
    with open(os.path.join(work, "error_log")) as f:
        log = f.read()
    return {
        "waiting (async)": log.count("waiting for the response (async)"),
        "ready (async)": log.count("response ready (async)"),
        "timeout (async)": log.count("timeout waiting for the response"),
        "abandoned": log.count("abandoned by its continuation"),
        "crashes": log.count("exit signal"),
        "errors": sum(1 for l in log.splitlines() if ":error]" in l or ":crit]" in l
                      or ":emerg]" in l),
    }


report = []
MODES = {"sync": "ProxyAsyncDelay -1", "async": "ProxyAsyncDelay 0\n    ProxyAsyncIdleTimeout 2"}
for mode in os.environ.get("MODES", "sync async").split():
    conf = MODES[mode]
    p = start(conf)
    try:
        elapsed, ok, statuses = concurrent(10, 1)
        report.append("%s: 10 concurrent requests, backend 1s, 2 workers: %.2fs, all ok: %s %s"
                      % (mode, elapsed, ok, statuses if not ok else ""))
        if mode == "async":
            c = http.client.HTTPConnection("127.0.0.1", FRONT, timeout=20)
            seq = [get("/slow?d=0.3&k=%d" % i, conn=c) for i in range(3)]
            c.close()
            report.append("async: keepalive, 3 requests on one connection: %s"
                          % [s for s, b in seq])
            status, _ = get("/slow?d=4")
            report.append("async: backend 4s > ProxyAsyncIdleTimeout 2s: %d" % status)
        # A response timeout is a 504 in both modes
        status, _ = get("/to?d=4")
        report.append("%s: backend 4s > timeout=2: %d%s"
                      % (mode, status, "" if status == 504 else " FAIL (504 expected)"))
        report.append("%s: error_log: %s" % (mode, log_findings()))
    finally:
        report.append("%s: %s" % (mode, stop(p)))
backend.shutdown()
print("\n".join(report))
