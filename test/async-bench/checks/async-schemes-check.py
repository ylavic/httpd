"""Check mod_proxy_ajp, mod_proxy_scgi and mod_proxy_uwsgi waiting for the
backend's response and for a connection of an exhausted pool without holding
a worker thread, against schemebackend.

usage: MODES="sync async" SCHEMES="ajp scgi uwsgi" \\
       python3 -I async-schemes-check.py HTTPD_PREFIX WORKDIR
"""

import http.client
import os
import signal
import subprocess
import sys
import threading
import time

prefix, work = sys.argv[1], sys.argv[2]
os.makedirs(work, exist_ok=True)
FRONT = 18432
PORTS = {"ajp": 18433, "scgi": 18434, "uwsgi": 18435}
DOWN = 18436
here = os.path.dirname(os.path.abspath(__file__))
backend = subprocess.Popen([os.path.join(here, "..", "schemebackend")]
                           + ["-%s=127.0.0.1:%d" % sp for sp in PORTS.items()])

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{front}
PidFile "{work}/httpd.pid"
ErrorLog "{work}/error_log"
LogLevel warn proxy:trace5 mpm_event:debug
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_ajp_module modules/mod_proxy_ajp.so
LoadModule proxy_scgi_module modules/mod_proxy_scgi.so
LoadModule proxy_uwsgi_module modules/mod_proxy_uwsgi.so
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
{asyncconf}
"""

# Distinct worker URLs, not shared (timeout= and max= apply)
PASS = """ProxyPass "/{s}/" "{s}://127.0.0.1:{port}/{s}/"
ProxyPass "/{s}-to/" "{s}://127.0.0.1:{port}/{s}-to/" timeout=1
ProxyPass "/{s}-pool/" "{s}://127.0.0.1:{port}/{s}-pool/" max=1
ProxyPass "/{s}-down/" "{s}://127.0.0.1:{down}/"
"""


def start(async_conf, schemes):
    conf = CONF.format(prefix=prefix, work=work, front=FRONT, asyncconf=async_conf)
    conf += "".join(PASS.format(s=s, port=PORTS[s], down=DOWN) for s in schemes)
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(conf)
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


def request(method, path, body=None, timeout=20):
    c = http.client.HTTPConnection("127.0.0.1", FRONT, timeout=timeout)
    try:
        c.request(method, path, body=body)
        r = c.getresponse()
        return r.status, r.read(), r.getheader("X-Body")
    except (http.client.HTTPException, OSError) as e:
        return type(e).__name__, b"", None
    finally:
        c.close()


def timed(fn, *args):
    t0 = time.monotonic()
    r = fn(*args)
    return r, round(time.monotonic() - t0, 2)


def concurrent(n, path, check):
    res = [None] * n

    def one(i):
        res[i] = request("GET", "%s&i=%d" % (path, i), timeout=30)
    t0 = time.monotonic()
    ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    ok = all(check(r) for r in res)
    return round(time.monotonic() - t0, 2), ok, [r[0] for r in res] if not ok else ""


def pool(s):
    """4 requests of 0.5s on a pool of 1 connection, and a quick request to
    another worker 0.1s later: how long the quick one waits for a thread."""
    res = {}

    def slow():
        res["pool"] = concurrent(4, "/%s-pool/p?d=500" % s, lambda r: r[0] == 200)
    t = threading.Thread(target=slow)
    t.start()
    time.sleep(0.1)
    res["quick"] = timed(request, "GET", "/%s/q?d=0" % s)
    t.join()
    return res["pool"], (res["quick"][0][0], res["quick"][1])


def log_findings():
    with open(os.path.join(work, "error_log")) as f:
        log = f.read()
    return {
        "waiting (async)": log.count("proxy: waiting for the backend (async)"),
        "pool waits (async)": log.count("proxy: waiting for a connection to"),
        "timeouts logged": (log.count("Script timed out before returning headers")
                            + log.count("timeout waiting for the response of")
                            + log.count("read response failed")),
        "crashes": log.count("exit signal"),
        "errors": sum(1 for l in log.splitlines() if ":error]" in l or ":crit]" in l
                      or ":emerg]" in l),
    }


report = []
MODES = {"sync": "ProxyAsyncDelay -1", "async": "ProxyAsyncDelay 0"}
schemes = os.environ.get("SCHEMES", "ajp scgi uwsgi").split()
ok512 = lambda r: r[0] == 200 and r[1] == b"x" * 512
for mode in os.environ.get("MODES", "sync async").split():
    p = start(MODES[mode], schemes)
    try:
        for s in schemes:
            m = "%s %s" % (mode, s)
            r, t = timed(request, "GET", "/%s/a?d=0" % s)
            report.append("%s: one request: %s, ok: %s, %ss" % (m, r[0], ok512(r), t))
            report.append("%s: 10 concurrent 1s responses, 2 workers: %ss, all ok: %s %s"
                          % ((m,) + concurrent(10, "/%s/slow?d=1000" % s, ok512)))
            r, t = timed(request, "GET", "/%s-to/t?d=3000" % s)
            # uwsgi: no status line within the timeout is a 504
            report.append("%s: timeout=1 vs a 3s backend: %s in %ss%s"
                          % (m, r[0], t, (": OK" if r[0] == 504 else ": FAIL")
                             if s == "uwsgi" else ""))
            r, t = timed(request, "GET", "/%s/big?s=%d" % (s, 1 << 20))
            report.append("%s: 1MB response: %s, %d bytes, %ss" % (m, r[0], len(r[1]), t))
            r, t = timed(request, "POST", "/%s/post?d=300" % s, b"y" * 100000)
            report.append("%s: 100KB POST, 0.3s backend: %s, body seen: %s, %ss"
                          % (m, r[0], r[2], t))
            r, t = timed(request, "GET", "/%s/c?d=500&close=0" % s)
            report.append("%s: backend closing without answering (0.5s): %s in %ss" % (m, r[0], t))
            r, t = timed(request, "GET", "/%s-down/d" % s)
            report.append("%s: backend down: %s in %ss" % (m, r[0], t))
            report.append("%s: pool of 1, 4 x 0.5s (elapsed, ok), quick request (status, wait): %s"
                          % (m, pool(s)))
        report.append("%s: error_log: %s" % (mode, log_findings()))
    finally:
        report.append("%s: %s" % (mode, stop(p)))
        os.replace(os.path.join(work, "error_log"), os.path.join(work, "error_log." + mode))
backend.terminate()
print("\n".join(report))
