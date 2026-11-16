"""Check requests waiting for a usable balancer member (the balancer's
timeout=) without holding a worker thread: a member put in error (its backend
down, retry=1) while the backend comes back, requests waiting until it's
retried, a quick request to another location meanwhile.

usage: MODES="sync async" python3 -I async-balancer-wait-check.py HTTPD_PREFIX WORKDIR
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
FRONT, MEMBER, OTHER = 18432, 18433, 18434
here = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.join(here, "..", "backend")
other = subprocess.Popen([BACKEND, "-addr", "127.0.0.1:%d" % OTHER])

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{front}
PidFile "{work}/httpd.pid"
ErrorLog "{work}/error_log"
LogLevel warn proxy:trace5 proxy_balancer:trace5 mpm_event:debug
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule slotmem_shm_module modules/mod_slotmem_shm.so
LoadModule lbmethod_byrequests_module modules/mod_lbmethod_byrequests.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule proxy_balancer_module modules/mod_proxy_balancer.so
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
<Proxy "balancer://b">
    BalancerMember "http://127.0.0.1:{member}" retry=1
    ProxySet timeout=3 forcerecovery=off nofailover=On
</Proxy>
ProxyPass "/b/" "balancer://b/"
ProxyPass "/other/" "http://127.0.0.1:{other}/"
"""


def start(async_conf):
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(CONF.format(prefix=prefix, work=work, front=FRONT, member=MEMBER, other=OTHER,
                            asyncconf=async_conf))
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


def get(path, timeout=20):
    c = http.client.HTTPConnection("127.0.0.1", FRONT, timeout=timeout)
    t0 = time.monotonic()
    try:
        c.request("GET", path)
        r = c.getresponse()
        r.read()
        return r.status, round(time.monotonic() - t0, 2)
    except (http.client.HTTPException, OSError) as e:
        return type(e).__name__, round(time.monotonic() - t0, 2)
    finally:
        c.close()


def waiting(n, backend_up):
    """The member in error, n requests wait for it; the quick request to
    another location 0.2s later."""
    first = get("/b/first")  # the member's backend is down: 503, in error
    member = subprocess.Popen([BACKEND, "-addr", "127.0.0.1:%d" % MEMBER]) if backend_up else None
    res = [None] * n

    def one(i):
        res[i] = get("/b/w?i=%d" % i)
    ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    time.sleep(0.2)
    quick = get("/other/q")
    for t in ts:
        t.join()
    if member:
        member.terminate()
        member.wait()
    return first, res, quick


def log_findings():
    with open(os.path.join(work, "error_log")) as f:
        log = f.read()
    return {
        "waiting (async)": log.count("waiting for a usable worker (async)"),
        "all in error": log.count("All workers are in error state"),
        "crashes": log.count("exit signal"),
    }


report = []
MODES = {"sync": "ProxyAsyncDelay -1", "async": "ProxyAsyncDelay 0"}
for mode in os.environ.get("MODES", "sync async").split():
    p = start(MODES[mode])
    try:
        first, res, quick = waiting(6, True)
        report.append("%s: member in error (%s), backend back, 6 waiting on 2 workers: %s"
                      % (mode, first, res))
        report.append("%s: a quick request meanwhile: %s" % (mode, quick))
        time.sleep(1.5)
        first, res, quick = waiting(2, False)
        report.append("%s: member in error (%s), backend still down, 2 waiting: %s"
                      % (mode, first, res))
        report.append("%s: a quick request meanwhile: %s" % (mode, quick))
        report.append("%s: error_log: %s" % (mode, log_findings()))
    finally:
        report.append("%s: %s" % (mode, stop(p)))
        os.replace(os.path.join(work, "error_log"), os.path.join(work, "error_log." + mode))
other.terminate()
print("\n".join(report))
