"""Check internally redirected requests to proxied URLs (an ErrorDocument
proxied to a slow backend, over http and fcgi): they don't suspend, their
caller (ap_internal_redirect()) going on once the handler returns. Also the
ErrorDocument of a request that waited for its backend asynchronously
(ProxyErrorOverride), proxied to the same backend over http: the redirected
request shares r->pool and reuses the backend's connection, and must not see
the first request's states.

usage: MODES="sync async" python3 -I async-redirect-check.py HTTPD_PREFIX WORKDIR
"""

import http.client
import os
import shutil
import signal
import subprocess
import sys
import threading
import time

prefix, work = sys.argv[1], sys.argv[2]
os.makedirs(os.path.join(work, "htdocs"), exist_ok=True)
FRONT, HTTP, FCGI = 18432, 18433, 18434
here = os.path.dirname(os.path.abspath(__file__))
backends = [subprocess.Popen([os.path.join(here, "..", "backend"),
                              "-addr", "127.0.0.1:%d" % HTTP]),
            subprocess.Popen([os.path.join(here, "..", "fcgibackend"),
                              "-addr", "127.0.0.1:%d" % FCGI])]

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{front}
PidFile "{work}/httpd.pid"
ErrorLog "{work}/error_log"
LogLevel warn proxy:trace5 proxy_http:trace5 mpm_event:debug
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule proxy_fcgi_module modules/mod_proxy_fcgi.so
ServerName localhost
DocumentRoot "{work}/htdocs"
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
ProxyPass "/h/" "http://127.0.0.1:{http}/h/"
ProxyPass "/f/" "fcgi://127.0.0.1:{fcgi}/f/"
<Location "/mh/">
    ErrorDocument 404 "/h/e?d=300"
</Location>
<Location "/mf/">
    ErrorDocument 404 "/f/e?d=300"
</Location>
ProxyPass "/hk/" "http://127.0.0.1:{http}/hk/"
<Location "/hk/">
    ProxyErrorOverride On
    ErrorDocument 500 "/hk/e?s=600"
</Location>
"""


def start(async_conf):
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(CONF.format(prefix=prefix, work=work, front=FRONT, http=HTTP, fcgi=FCGI,
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


def get(path, timeout=10):
    c = http.client.HTTPConnection("127.0.0.1", FRONT, timeout=timeout)
    try:
        c.request("GET", path)
        r = c.getresponse()
        return r.status, r.read()
    except (http.client.HTTPException, OSError) as e:
        return type(e).__name__, b""
    finally:
        c.close()


def backend_conns(port):
    """the established connections to the backend's port (ss, else netstat,
    e.g. on FreeBSD)"""
    if shutil.which("ss"):
        out = subprocess.run(["ss", "-Htn", "state", "established", "dst",
                              "127.0.0.1:%d" % port], capture_output=True, text=True).stdout
        return len(out.splitlines())
    out = subprocess.run(["netstat", "-n", "-p", "tcp"], capture_output=True, text=True).stdout
    return sum(1 for line in out.splitlines()
               if "ESTABLISHED" in line and line.split()[4] == "127.0.0.1.%d" % port)


def overridden(n):
    """n requests on one connection, each waiting 0.3s for a 500 from the http
    backend, overridden by the ErrorDocument (600 bytes) from the same
    backend; the statuses and body lengths, and the backend connections
    opened for them (1 when the redirected requests reuse the connection)."""
    before = backend_conns(HTTP)
    c = http.client.HTTPConnection("127.0.0.1", FRONT, timeout=10)
    res = []
    try:
        for i in range(n):
            c.request("GET", "/hk/x?d=300&st=500&i=%d" % i)
            r = c.getresponse()
            body = r.read()
            res.append((r.status, len(body)))
    except (http.client.HTTPException, OSError) as e:
        res.append(type(e).__name__)
    finally:
        c.close()
    return res, backend_conns(HTTP) - before


def concurrent(n, path):
    res = [None] * n

    def one(i):
        res[i] = get(path)
    ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return [(st, len(body)) for st, body in res]


def log_findings():
    with open(os.path.join(work, "error_log")) as f:
        log = f.read()
    return {
        "invalid status": log.count("Invalid response status"),
        "waiting (async)": log.count("waiting for the"),
        "crashes": log.count("exit signal"),
        "errors": sum(1 for l in log.splitlines() if ":error]" in l or ":crit]" in l
                      or ":emerg]" in l),
    }


report = []
MODES = {"sync": "ProxyAsyncDelay -1", "async": "ProxyAsyncDelay 0"}
for mode in os.environ.get("MODES", "sync async").split():
    p = start(MODES[mode])
    try:
        for scheme in ("h", "f"):
            st, body = get("/m%s/missing.html" % scheme)
            report.append("%s: 404 with an ErrorDocument proxied over %s (0.3s): %s, %d bytes, "
                          "backend body: %s" % (mode, "http" if scheme == "h" else "fcgi",
                                                st, len(body), body == b"x" * 512))
            report.append("%s: 4 concurrent of them: %s"
                          % (mode, concurrent(4, "/m%s/missing.html" % scheme)))
        report.append("%s: 3 backend 500s (0.3s) overridden by an ErrorDocument proxied over "
                      "http to the same backend ((status, body length)..., new backend "
                      "conns): %s" % (mode, overridden(3)))
        report.append("%s: error_log: %s" % (mode, log_findings()))
    finally:
        report.append("%s: %s" % (mode, stop(p)))
        os.replace(os.path.join(work, "error_log"), os.path.join(work, "error_log." + mode))
for b in backends:
    b.terminate()
print("\n".join(report))
