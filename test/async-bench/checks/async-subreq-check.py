"""Check subrequests run asynchronously (ap_run_sub_req_async()) through
mod_aptest's "AptestSubreq" handler, which runs n subrequests in turn before
the other handlers of its locations, their output passed to the client or
captured by an output filter of the subrequest: proxied subrequests suspended
while mod_proxy waits for the backend (1, 3 and 8 of them per request, more
than the descriptors the MPM keeps per connection), a subrequest suspended by
mod_aptest's AptestSuspend then resumed to the next handler (a static file),
a nested subrequest (a subrequest running its own), the next handler after the
subrequests (DECLINED to a static file), a subrequest reaching its timeout
(504 to the caller), many clients on few threads, pipelined requests behind
requests running subrequests, mod_auth_form's replay of a login form's
request as a subrequest (here suspended by AptestSuspend), and a graceful
stop during subrequests. "sync"
runs them with AsyncRequests Off (the subrequests block: the same responses,
the threads held), "async" with the waits in the MPM (no thread held while a
subrequest waits). Then mod_include's include virtual of a proxied URL, which
stays blocking in both modes (a thread held: mod_include runs its subrequests
from a filter, which can't suspend), with the same output.

mod_aptest is built from ../../pyhttpd/mod_aptest with the install's apxs
into WORKDIR unless MOD_APTEST_SO is given.

usage: MODES="sync async" python3 -I async-subreq-check.py HTTPD_PREFIX [MOD_APTEST_SO] WORKDIR
"""

import hashlib
import http.client
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

here = os.path.dirname(os.path.abspath(__file__))
if len(sys.argv) > 3:
    prefix, aptest, work = sys.argv[1], sys.argv[2], sys.argv[3]
else:
    prefix, aptest, work = sys.argv[1], None, sys.argv[2]
os.makedirs(work, exist_ok=True)
PORT, BACKEND = 18455, 18456
THREADS = 4
BACKEND_MS = 100        # the proxied subrequests' backend delay
SUSPEND_MS = 300        # AptestSuspend's wait in a subrequest
INC_MS = 300            # the backend delay of mod_include's subrequest
TIMEOUT_MS = 300        # the subrequests' timeout of the timeout case

apxs = os.path.join(prefix, "bin", "apxs")
if not aptest:
    src = os.path.join(here, "..", "..", "pyhttpd", "mod_aptest", "mod_aptest.c")
    bdir = os.path.join(work, "aptest")
    os.makedirs(bdir, exist_ok=True)
    shutil.copy(src, bdir)
    r = subprocess.run([apxs, "-c", "mod_aptest.c"], cwd=bdir, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("building mod_aptest failed:\n" + r.stdout + r.stderr)
    aptest = os.path.join(bdir, ".libs", "mod_aptest.so")

docs = os.path.join(work, "htdocs")
FILES = {
    "s/file.txt": b"static file\n",
    "scd/file.txt": b"static file after subrequests\n",
    "long/file.txt": b"long\n",
    "af/file.txt": b"replayed after the login form\n",
    "inc/index.shtml": b'before\n<!--#include virtual="/p/x?d=%d" -->\nafter\n' % INC_MS,
}
for name, data in FILES.items():
    os.makedirs(os.path.dirname(os.path.join(docs, name)), exist_ok=True)
    with open(os.path.join(docs, name), "wb") as f:
        f.write(data)

r = subprocess.run([os.path.join(prefix, "bin", "htpasswd"), "-cb",
                    os.path.join(work, "htpasswd"), "u", "p"], capture_output=True, text=True)
if r.returncode != 0:
    raise SystemExit("htpasswd failed:\n" + r.stdout + r.stderr)

backend = subprocess.Popen([os.path.join(here, "..", "backend"),
                            "-addr", "127.0.0.1:%d" % BACKEND])

# A streamed backend response: several reads (waits) per subrequest, so that
# its backend connection's descriptor is kept by the MPM from the second one
STREAM = "s=65536&c=4096&i=20000"

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{port}
PidFile "{work}/httpd.pid"
ErrorLog "{work}/error_log"
LogLevel warn aptest:info mpm_event:trace4 proxy:trace5 proxy_http:trace5 auth_form:trace5
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule status_module modules/mod_status.so
LoadModule include_module modules/mod_include.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule session_module modules/mod_session.so
LoadModule session_cookie_module modules/mod_session_cookie.so
LoadModule request_module modules/mod_request.so
LoadModule authn_core_module modules/mod_authn_core.so
LoadModule authn_file_module modules/mod_authn_file.so
LoadModule authz_user_module modules/mod_authz_user.so
LoadModule auth_form_module modules/mod_auth_form.so
LoadModule aptest_module {aptest}
ServerName localhost
DocumentRoot "{work}/htdocs"
StartServers 1
ServerLimit 1
ThreadLimit {threads}
ThreadsPerChild {threads}
MaxRequestWorkers {threads}
MinSpareThreads 1
MaxSpareThreads {threads}
Timeout 5
KeepAliveTimeout 5
GracefulShutdownTimeout 5
AcceptFilter http none
ExtendedStatus On
LogFormat "%r %>s %D" t
CustomLog "{work}/access_log" t
{modeconf}
ProxyPass "/p/" "http://127.0.0.1:{backend}/p/"
<Location "/s/">
    AptestSuspend {suspend_ms} declined
</Location>
<Location "/sp/">
    AptestSubreq "/p/x?d={backend_ms}" 1 passed ok
</Location>
<Location "/sc1/">
    AptestSubreq "/p/x?d={backend_ms}" 1 captured ok
</Location>
<Location "/sc3/">
    AptestSubreq "/p/x?d={backend_ms}" 3 captured ok
</Location>
<Location "/sc8/">
    AptestSubreq "/p/x?{stream}" 8 captured ok
</Location>
<Location "/ss/">
    AptestSubreq "/s/file.txt" 2 captured ok
</Location>
<Location "/scd/">
    AptestSubreq "/p/x?d={backend_ms}" 2 captured declined
</Location>
<Location "/inner/">
    AptestSubreq "/p/x?d={backend_ms}" 2 passed ok
</Location>
<Location "/nest/">
    AptestSubreq "/inner/x" 1 passed ok
</Location>
<Location "/sto/">
    AptestSubreq "/p/x?d=2000" 1 captured ok timeout {timeout_ms}
</Location>
<Location "/long/">
    AptestSubreq "/p/x?d=3000" 1 captured declined
</Location>
<Location "/inc/">
    Options +Includes
    SetOutputFilter INCLUDES
</Location>
<Location "/af/">
    AptestSuspend {suspend_ms} declined
    AuthType form
    AuthName af
    AuthFormProvider file
    AuthUserFile "{work}/htpasswd"
    Session On
    SessionCookieName session path=/
    Require valid-user
</Location>
<Location "/server-status">
    SetHandler server-status
</Location>
"""
MODES = {"sync": "AsyncRequests Off", "async": ""}


def start(modeconf):
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(CONF.format(prefix=prefix, work=work, port=PORT, backend=BACKEND,
                            aptest=aptest, threads=THREADS, backend_ms=BACKEND_MS,
                            suspend_ms=SUSPEND_MS, timeout_ms=TIMEOUT_MS,
                            stream=STREAM, modeconf=modeconf))
    for name in ("error_log", "access_log"):
        open(os.path.join(work, name), "w").close()
    p = subprocess.Popen([os.path.join(prefix, "bin", "httpd"), "-f",
                          os.path.join(work, "httpd.conf"), "-DFOREGROUND"])
    if not serving(10):
        stop(p)
        raise SystemExit("httpd didn't start")
    return p


def serving(limit):
    """wait up to limit seconds for the server to answer"""
    t0 = time.monotonic()
    while time.monotonic() - t0 < limit:
        try:
            c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=1)
            c.request("GET", "/nothing")
            c.getresponse().read()
            c.close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def kill_tree(p):
    for kid in subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True,
                              text=True).stdout.split():
        os.kill(int(kid), signal.SIGKILL)
    os.kill(p.pid, signal.SIGKILL)
    p.wait(10)


def stop(p):
    if p.poll() is not None:
        return "stopped already"
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
        return "stopped"
    except subprocess.TimeoutExpired:
        kill_tree(p)
        return "STOP HUNG (killed)"


def get(path, timeout=30):
    """status, body, the AP-Test-Subreq header, the time taken"""
    t0 = time.monotonic()
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    try:
        c.request("GET", path)
        r = c.getresponse()
        return (r.status, r.read(), r.getheader("AP-Test-Subreq"),
                round(time.monotonic() - t0, 2))
    except (http.client.HTTPException, OSError) as e:
        return type(e).__name__, b"", None, round(time.monotonic() - t0, 2)
    finally:
        c.close()


FORM = (b"httpd_username=u&httpd_password=p&httpd_method=GET"
        b"&httpd_mimetype=text/plain&httpd_body=")


def post_form(path, timeout=30):
    """status, body, the time taken of a login form posted to path"""
    t0 = time.monotonic()
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    try:
        c.request("POST", path, body=FORM,
                  headers={"Content-Type": "application/x-www-form-urlencoded"})
        r = c.getresponse()
        return r.status, r.read(), round(time.monotonic() - t0, 2)
    except (http.client.HTTPException, OSError) as e:
        return type(e).__name__, b"", round(time.monotonic() - t0, 2)
    finally:
        c.close()


def status_auto():
    st, body, _, _ = get("/server-status?auto", timeout=5)
    return body if st == 200 else b""


def busy_workers():
    m = re.search(rb"BusyWorkers: (\d+)", status_auto())
    return int(m.group(1)) if m else None


def wait_idle(limit=5):
    t0 = time.monotonic()
    while time.monotonic() - t0 < limit:
        if busy_workers() == 1:
            return True
        time.sleep(0.05)
    return False


class Sampler:
    """BusyWorkers at the given times (s) from now, in the background, the
    status request's own excluded"""

    def __init__(self, times):
        self.samples = []
        self.t = threading.Thread(target=self.run, args=(times,))
        self.t0 = time.monotonic()
        self.t.start()

    def run(self, times):
        for when in times:
            time.sleep(max(0, when - (time.monotonic() - self.t0)))
            busy = busy_workers()
            self.samples.append(None if busy is None else busy - 1)

    def held(self):
        self.t.join()
        vals = [v for v in self.samples if v is not None]
        return max(vals) if vals else None


def parallel(n, fn):
    res = [None] * n

    def one(i):
        try:
            res[i] = fn(i)
        except Exception as e:
            res[i] = ("EXC", type(e).__name__)
    t0 = time.monotonic()
    ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return res, round(time.monotonic() - t0, 2)


def read_responses(s, n):
    """n responses read from s: (status, body) each, None for those missing"""
    buf, out = b"", []
    while len(out) < n:
        while b"\r\n\r\n" not in buf:
            b = s.recv(65536)
            if not b:
                return out + [None] * (n - len(out))
            buf += b
        head, _, buf = buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        status = int(lines[0].split(b" ")[1])
        hdrs = {}
        for l in lines[1:]:
            k, _, v = l.partition(b":")
            hdrs[k.strip().lower()] = v.strip()
        if hdrs.get(b"transfer-encoding") == b"chunked":
            body = b""
            while True:
                while b"\r\n" not in buf:
                    buf += s.recv(65536)
                size, _, buf = buf.partition(b"\r\n")
                k = int(size.split(b";")[0], 16)
                while len(buf) < k + 2:
                    buf += s.recv(65536)
                body, buf = body + buf[:k], buf[k + 2:]
                if k == 0:
                    break
        else:
            k = int(hdrs.get(b"content-length", b"0"))
            while len(buf) < k:
                b = s.recv(65536)
                if not b:
                    break
                buf += b
            body, buf = buf[:k], buf[k:]
        out.append((status, body))
    return out


def pipelined(paths):
    s = socket.create_connection(("127.0.0.1", PORT), timeout=30)
    try:
        s.sendall(b"".join(b"GET %s HTTP/1.1\r\nHost: x\r\n\r\n" % p.encode()
                           for p in paths))
        return read_responses(s, len(paths))
    except OSError as e:
        return [type(e).__name__]
    finally:
        s.close()


def log():
    with open(os.path.join(work, "error_log")) as f:
        return f.read()


def verdict(ok):
    return "OK" if ok else "FAIL"


def short(r):
    return repr(r)[:100]


def summary(hdr_or_body):
    """the fields of an "aptest-subreq" summary (header or body line)"""
    if isinstance(hdr_or_body, bytes):
        m = re.search(rb"aptest-subreq: (.*)\n", hdr_or_body)
        hdr_or_body = m.group(1).decode() if m else ""
    return dict(f.split("=", 1) for f in (hdr_or_body or "").split() if "=" in f)


BACKEND_BODY = None     # the backend's 512 bytes, fetched once through /p/


def captured(n, body=None):
    """the "captured" field for n backend bodies of 512 bytes (or n bodies)"""
    data = (body if body is not None else BACKEND_BODY) * n
    return "%d:%s" % (len(data), hashlib.md5(data).hexdigest()[:8])


report = []
responses = {}   # mode -> case -> (status, body md5, summary without async)
for mode in os.environ.get("MODES", "sync async").split():
    is_async = mode == "async"
    resp = responses[mode] = {}
    p = start(MODES[mode])
    try:
        def case(name, st, body, hdr, ok, extra=""):
            fields = summary(hdr) if hdr else summary(body if isinstance(body, bytes) else b"")
            fields.pop("async", None)
            resp[name] = (st, hashlib.md5(re.sub(rb"async=\d+", b"", body)).hexdigest()[:8]
                          if isinstance(body, bytes) else body, sorted(fields.items()))
            report.append("%s: %s: %s %s%s: %s" % (mode, name, st, short(hdr or body)[:70],
                                                   extra, verdict(ok)))

        def nasync(fields, n):
            """the subrequests that suspended: all in async mode, none in sync"""
            return fields.get("async") == str(n if is_async else 0)

        if BACKEND_BODY is None:
            st, BACKEND_BODY, _, _ = get("/p/x")
            if st != 200 or len(BACKEND_BODY) != 512:
                raise SystemExit("backend not answering: %s" % short(BACKEND_BODY))

        # One request of each kind
        st, body, hdr, t = get("/sp/x")
        f = summary(body)
        case("1 proxied subrequest, passed", st, body, None,
             st == 200 and body.startswith(BACKEND_BODY) and f.get("statuses") == "200"
             and nasync(f, 1))

        st, body, hdr, t = get("/sc1/x")
        f = summary(hdr)
        case("1 proxied subrequest, captured", st, body, hdr,
             st == 200 and f.get("statuses") == "200" and nasync(f, 1)
             and f.get("captured") == captured(1) and body.startswith(b"aptest-subreq: "))

        st, body, hdr, t = get("/sc3/x")
        f = summary(hdr)
        case("3 proxied subrequests in turn, captured", st, body, hdr,
             st == 200 and f.get("statuses") == "200,200,200" and nasync(f, 3)
             and f.get("captured") == captured(3))

        before = log()
        st, body, hdr, t = get("/sc8/x")
        f = summary(hdr)
        after = log()[len(before):]
        kept_max = after.count("(EVENT_KEPT_MAX)")
        left = after.count("left by the subrequest")
        bwaits = after.count("waiting for the connection (in) (async)")
        stream_len = int(re.search(r"s=(\d+)", STREAM).group(1))
        case("8 proxied subrequests streamed (backend's descriptor kept)", st, body, hdr,
             st == 200 and f.get("statuses") == ",".join(["200"] * 8) and nasync(f, 8)
             and f.get("captured") == captured(8, b"x" * stream_len) and kept_max == 0,
             " [backend waits %d, EVENT_KEPT_MAX lines %d, contexts left kept %d]"
             % (bwaits, kept_max, left))

        st, body, hdr, t = get("/ss/x")
        f = summary(hdr)
        case("2 subrequests suspended by AptestSuspend, resumed to a static file",
             st, body, hdr, st == 200 and f.get("statuses") == "200,200" and nasync(f, 2)
             and f.get("captured") == captured(2, FILES["s/file.txt"]))

        st, body, hdr, t = get("/scd/file.txt")
        f = summary(hdr)
        case("2 proxied subrequests, then DECLINED to a static file", st, body, hdr,
             st == 200 and body == FILES["scd/file.txt"] and f.get("statuses") == "200,200"
             and nasync(f, 2) and f.get("captured") == captured(2))

        st, body, hdr, t = get("/nest/x")
        inner = re.findall(rb"aptest-subreq: (.*)\n", body)
        f = summary(body[body.rfind(b"aptest-subreq: "):] if inner else b"")
        fi = summary(b"aptest-subreq: " + inner[0] + b"\n") if inner else {}
        case("a nested subrequest (2 proxied subrequests of a subrequest), passed",
             st, body, None,
             st == 200 and body.startswith(BACKEND_BODY * 2) and len(inner) == 2
             and fi.get("statuses") == "200,200" and nasync(fi, 2)
             and f.get("statuses") == "200" and nasync(f, 1))

        before = log()
        st, body, hdr, t = get("/sto/x")
        f = summary(hdr)
        time.sleep(0.1)
        sto_log = log()[len(before):]
        reached = sto_log.count("subrequest's timeout reached")
        # mod_proxy's own error for the backend's timeout, expected
        sto_errors = sum(1 for l in sto_log.splitlines() if ":error]" in l)
        if is_async:
            # The deadline caps the subrequest's wait for the backend
            ok = (st == 200 and f.get("statuses") == "504" and nasync(f, 1)
                  and reached == 1 and t < 1.5)
        else:
            # Blocking: no deadline (the asynchronous waits only)
            ok = st == 200 and f.get("statuses") == "200" and nasync(f, 0) and t >= 2
        report.append("%s: a subrequest over its timeout (%dms, backend 2000ms): %s %s in "
                      "%ss, timeouts logged %d: %s" % (mode, TIMEOUT_MS, st, f.get("statuses"),
                                                       t, reached, verdict(ok)))

        res = pipelined(["/s/file.txt?1", "/sc3/x", "/scd/file.txt", "/p/x?d=10"])
        ok = (len(res) == 4 and None not in res
              and res[0] == (200, FILES["s/file.txt"])
              and res[1][0] == 200 and res[1][1].startswith(b"aptest-subreq: ")
              and res[2] == (200, FILES["scd/file.txt"])
              and res[3][0] == 200 and res[3][1] == BACKEND_BODY)
        case("4 pipelined requests, some running subrequests, in order", "-",
             repr([r[0] if r else None for r in res]), None, ok)

        # mod_auth_form: a login form posted to a protected location, its
        # request replayed (GET) as a subrequest by the redirect handler, here
        # suspended by AptestSuspend (as the main request is first), then
        # resumed to the static file: one request, then 16 clients at once
        before = log()
        st, body, t = post_form("/af/file.txt")
        case("mod_auth_form's replay of the login form's request", st, body, None,
             st == 200 and body == FILES["af/file.txt"])
        wait_idle()
        n = 16 if is_async else THREADS
        smp = Sampler([SUSPEND_MS / 2000.0, 1.5 * SUSPEND_MS / 1000.0])
        res, t = parallel(n, lambda i: post_form("/af/file.txt?i=%d" % i))
        busy = smp.held()
        replays = log()[len(before):].count("subrequest suspended")
        ok = all(r[0] == 200 and r[1] == FILES["af/file.txt"] for r in res)
        if is_async:
            ok = ok and busy is not None and busy <= 1 and replays == n + 1
        else:
            ok = ok and replays == 0
        report.append("%s: %d login forms replayed by mod_auth_form at once: %ss, workers held "
                      "%s, replays suspended %d: %s" % (mode, n, t, busy, replays, verdict(ok)))

        # mod_include's include virtual of a proxied URL: blocking in both
        # modes (from the INCLUDES filter), the same output
        st, body, hdr, t = get("/inc/index.shtml")
        case("include virtual of a proxied URL (mod_include, blocking)", st, body, None,
             st == 200 and body == b"before\n" + BACKEND_BODY + b"\nafter\n")
        # (one thread left for mod_status' requests)
        wait_idle()
        n = THREADS - 1
        smp = Sampler([INC_MS / 3000.0, INC_MS / 2000.0])
        res, t = parallel(n, lambda i: get("/inc/index.shtml?i=%d" % i))
        busy = smp.held()
        ok = all(r[0] == 200 and r[1] == b"before\n" + BACKEND_BODY + b"\nafter\n"
                 for r in res) and busy == n
        report.append("%s: %d include virtual of a proxied URL at once: %ss, workers held %s "
                      "(blocking, phase B's): %s" % (mode, n, t, busy, verdict(ok)))

        # Many clients on THREADS threads (as many as don't wait for a worker
        # longer than Timeout when blocking): no worker held while the
        # subrequests wait for the backend
        wait_idle()
        n = 32 if is_async else THREADS
        smp = Sampler([BACKEND_MS / 2000.0, 1.5 * BACKEND_MS / 1000.0,
                       2.5 * BACKEND_MS / 1000.0])
        res, t = parallel(n, lambda i: get("/sc3/x?i=%d" % i))
        busy = smp.held()
        ok = all(r[0] == 200 and summary(r[2]).get("statuses") == "200,200,200"
                 and summary(r[2]).get("captured") == captured(3) for r in res)
        if is_async:
            ok = ok and busy is not None and busy <= 1 and t < 10 * 3 * BACKEND_MS / 1000
        report.append("%s: %d clients running 3 proxied subrequests each (backend %dms) on "
                      "%d threads: %ss, workers held %s, all ok: %s"
                      % (mode, n, BACKEND_MS, THREADS, t, busy, verdict(ok)))

        text = log()
        findings = {
            "abandoned": text.count("abandoned by its continuation"),
            "refused resumes": text.count("resumed while not suspended"),
            "run blocking (refused)": text.count("can't run the subrequest asynchronously"),
            "destroyed early": text.count("destroyed before it completed"),
            "contexts left kept": text.count("left by the subrequest"),
            "crashes": text.count("exit signal"),
            "errors": sum(1 for l in text.splitlines()
                          if (":error]" in l or ":crit]" in l or ":emerg]" in l)
                          and "MaxRequestWorkers" not in l) - sto_errors,
            "timeout case's errors (mod_proxy's)": sto_errors,
        }
        report.append("%s: error_log: %s: %s"
                      % (mode, findings, verdict(findings["crashes"] == 0
                                                 and findings["errors"] == 0
                                                 and findings["abandoned"] == 0
                                                 and findings["run blocking (refused)"] == 0
                                                 and findings["destroyed early"] == 0)))

        # Graceful stop during subrequests waiting 3s for the backend (as
        # many as the threads when blocking): they complete, no hang
        n = 8 if is_async else THREADS
        res = [None] * n

        def one(i):
            res[i] = get("/long/file.txt?i=%d" % i, timeout=20)[0]
        ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
        for th in ts:
            th.start()
        time.sleep(0.5)
        t0 = time.monotonic()
        p.send_signal(signal.SIGWINCH)
        try:
            p.wait(15)
            t = round(time.monotonic() - t0, 1)
        except subprocess.TimeoutExpired:
            kill_tree(p)
            t = None
        for th in ts:
            th.join()
        crashes = log().count("exit signal")
        ok = t is not None and t < 8 and not crashes and set(res) == {200}
        report.append("%s: graceful stop during %d subrequests waiting 3s for the backend: "
                      "stopped after %ss, statuses %s, crashes %d: %s"
                      % (mode, n, t, sorted(set(map(str, res))), crashes, verdict(ok)))
    finally:
        report.append("%s: %s" % (mode, stop(p)))
        os.replace(os.path.join(work, "error_log"), os.path.join(work, "error_log." + mode))

if len(responses) > 1:
    modes = list(responses)
    diff = [c for c in responses[modes[0]]
            if responses[modes[0]][c] != responses[modes[1]].get(c)]
    report.append("%s vs %s: the same responses: %s%s"
                  % (modes[0], modes[1], verdict(not diff), " (differ: %s)" % diff if diff else ""))
backend.send_signal(signal.SIGTERM)
backend.wait(10)
print("\n".join(report))
