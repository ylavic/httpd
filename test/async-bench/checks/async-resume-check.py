"""Check handler chains resumed after a suspension (ap_request_resume_suspended())
through mod_aptest's AptestSuspend handlers, which run before the others for
any request of their locations: a suspension then DECLINED to a static file,
or to mod_proxy (which suspends in turn, its end through the resume too), two
suspending handlers in a row, "ok" (the handler answers), a 403 with a local
and with a proxied ErrorDocument (an internal redirect, blocking),
"filter-error" (the output filters answered: one response), "twice" (a resume
before the handler returned SUSPENDED: refused and logged, a debug build
asserts), the suspending location in a subrequest (mod_include, blocking),
pipelined requests behind suspended ones, ExtendedStatus' durations (no time
counted while suspended), and a graceful stop during suspensions. "sync" runs
them with AsyncRequests Off (the handlers block: the same responses, the
threads held), "async" with the waits in the MPM (no thread held while
suspended).

mod_aptest is built from ../../pyhttpd/mod_aptest with the install's apxs
into WORKDIR unless MOD_APTEST_SO is given.

usage: MODES="sync async" python3 -I async-resume-check.py HTTPD_PREFIX [MOD_APTEST_SO] WORKDIR
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
PORT, BACKEND = 18447, 18448
THREADS = 4
SUSPEND = 0.3           # AptestSuspend's wait (s)
BACKEND_MS = 100        # the proxied requests' backend delay

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
# A debug build (AP_DEBUG) asserts on a refused resume: the child aborts
DEBUG = any("-DAP_DEBUG" in subprocess.run([apxs, "-q", v], capture_output=True,
                                           text=True).stdout
            for v in ("CFLAGS", "EXTRA_CPPFLAGS", "NOTEST_CPPFLAGS"))

docs = os.path.join(work, "htdocs")
FILES = {
    "s/file.txt": b"static file\n",
    "two/file.txt": b"static file two\n",
    "long/file.txt": b"long\n",
    "errdoc/403.html": b"error document 403\n",
    "inc/index.shtml": b'before\n<!--#include virtual="/s/file.txt" -->\nafter\n',
}
for name, data in FILES.items():
    os.makedirs(os.path.dirname(os.path.join(docs, name)), exist_ok=True)
    with open(os.path.join(docs, name), "wb") as f:
        f.write(data)

backend = subprocess.Popen([os.path.join(here, "..", "backend"),
                            "-addr", "127.0.0.1:%d" % BACKEND])

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{port}
PidFile "{work}/httpd.pid"
ErrorLog "{work}/error_log"
LogLevel warn aptest:info mpm_event:debug
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule status_module modules/mod_status.so
LoadModule include_module modules/mod_include.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
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
GracefulShutdownTimeout 3
AcceptFilter http none
ExtendedStatus On
LogFormat "%r %>s %D" t
CustomLog "{work}/access_log" t
{modeconf}
ProxyPass "/p/" "http://127.0.0.1:{backend}/p/"
ProxyPass "/pe/" "http://127.0.0.1:{backend}/pe/"
<Location "/s/">
    AptestSuspend {ms} declined
</Location>
<Location "/p/">
    AptestSuspend {ms} declined
</Location>
<Location "/two/">
    AptestSuspend {ms} declined
    AptestSuspend2 {ms} declined
</Location>
<Location "/ok/">
    AptestSuspend {ms} ok
</Location>
<Location "/e403/">
    AptestSuspend {ms} 403
    ErrorDocument 403 /errdoc/403.html
</Location>
<Location "/e403p/">
    AptestSuspend {ms} 403
    ErrorDocument 403 "/pe/err?d={backend_ms}&st=403"
</Location>
<Location "/fe/">
    AptestSuspend {ms} filter-error
</Location>
<Location "/twice/">
    AptestSuspend {ms} ok twice
</Location>
<Location "/long/">
    AptestSuspend 5000 declined
</Location>
<Location "/inc/">
    Options +Includes
    SetOutputFilter INCLUDES
</Location>
<Location "/server-status">
    SetHandler server-status
</Location>
"""
MODES = {"sync": "AsyncRequests Off", "async": ""}


def start(modeconf):
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(CONF.format(prefix=prefix, work=work, port=PORT, backend=BACKEND,
                            aptest=aptest, threads=THREADS, ms=int(SUSPEND * 1000),
                            backend_ms=BACKEND_MS, modeconf=modeconf))
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
    """status, body, the AP-Test-Suspend1/2 headers"""
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    try:
        c.request("GET", path)
        r = c.getresponse()
        return r.status, r.read(), (r.getheader("AP-Test-Suspend1"),
                                    r.getheader("AP-Test-Suspend2"))
    except (http.client.HTTPException, OSError) as e:
        return type(e).__name__, b"", (None, None)
    finally:
        c.close()


def status_auto():
    st, body, _ = get("/server-status?auto", timeout=5)
    return body if st == 200 else b""


def busy_workers():
    m = re.search(rb"BusyWorkers: (\d+)", status_auto())
    return int(m.group(1)) if m else None


def total_duration():
    m = re.search(rb"Total Duration: (\d+)", status_auto())
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


def raw_all(path):
    """everything sent for a request on a connection closed after it"""
    s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    data = b""
    try:
        s.sendall(b"GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
                  % path.encode())
        while True:
            b = s.recv(65536)
            if not b:
                break
            data += b
    except OSError:
        pass
    finally:
        s.close()
    return data


def log():
    with open(os.path.join(work, "error_log")) as f:
        return f.read()


def verdict(ok):
    return "OK" if ok else "FAIL"


def short(r):
    return repr(r)[:100]


report = []
responses = {}   # mode -> case -> (status, body md5), compared between modes
for mode in os.environ.get("MODES", "sync async").split():
    is_async = mode == "async"
    exp = "async" if is_async else "sync"
    resp = responses[mode] = {}
    p = start(MODES[mode])
    try:
        def case(name, st, body, ok, extra=""):
            resp[name] = (st, hashlib.md5(body).hexdigest()[:8] if isinstance(body, bytes)
                          else body)
            report.append("%s: %s: %s %s%s: %s" % (mode, name, st, short(body)[:40],
                                                   extra, verdict(ok)))

        # One request of each kind
        st, body, hdr = get("/s/file.txt")
        case("suspend, DECLINED, static file", st, body,
             st == 200 and body == FILES["s/file.txt"] and hdr == (exp, None))

        st, body, hdr = get("/p/x?d=%d" % BACKEND_MS)
        case("suspend, DECLINED, ProxyPass (suspending in turn)", st, body,
             st == 200 and len(body) == 512 and hdr[0] == exp)

        st, body, hdr = get("/two/file.txt")
        case("two suspending handlers, both DECLINED", st, body,
             st == 200 and body == FILES["two/file.txt"] and hdr == (exp, exp))

        st, body, hdr = get("/ok/x")
        case("suspend, ok", st, body, st == 200 and body == b"aptest-suspend1: ok\n"
             and hdr[0] == exp)

        st, body, hdr = get("/e403/x")
        case("suspend, 403, local ErrorDocument", st, body,
             st == 403 and body == FILES["errdoc/403.html"])

        st, body, hdr = get("/e403p/x")
        case("suspend, 403, proxied ErrorDocument", st, body,
             st == 403 and len(body) == 512)

        raw = raw_all("/fe/x")
        statuses = re.findall(rb"(?:^|\r\n)HTTP/1\.1 (\d{3}) ", raw)
        case("suspend, filter-error (the filters answered)",
             b",".join(statuses).decode(), raw.partition(b"\r\n\r\n")[2],
             statuses == [b"413"])

        st, body, hdr = get("/inc/index.shtml")
        case("the suspending location in a subrequest (include virtual)", st, body,
             st == 200 and body == b"before\nstatic file\n\nafter\n")

        res = pipelined(["/s/file.txt?1", "/ok/x", "/s/file.txt?2", "/p/x?d=10"])
        want = [(200, FILES["s/file.txt"]), (200, b"aptest-suspend1: ok\n"),
                (200, FILES["s/file.txt"])]
        ok = (len(res) == 4 and res[:3] == want and res[3] is not None
              and res[3][0] == 200 and len(res[3][1]) == 512)
        case("4 pipelined requests behind suspended ones, in order", "-",
             repr([r[0] if r else None for r in res]), ok)

        # Many clients on THREADS threads (as many as don't wait for a worker
        # longer than Timeout when blocking): no worker held while suspended,
        # nor while mod_proxy waits for the backend after the resume
        wait_idle()
        n = 64 if is_async else 2 * THREADS
        d0 = total_duration()
        smp = Sampler([SUSPEND / 2, SUSPEND / 2 + 0.05])
        res, t = parallel(n, lambda i: get("/s/file.txt?i=%d" % i))
        busy = smp.held()
        ok = all(r[0] == 200 and r[1] == FILES["s/file.txt"] for r in res)
        if is_async:
            ok = ok and busy is not None and busy <= 1 and t < 3 * SUSPEND
        wait_idle()
        d1 = total_duration()
        # The workers' time (ExtendedStatus): without the suspensions in async
        # mode, with them when blocking
        dur = None if d0 is None or d1 is None else d1 - d0
        if is_async:
            dok = dur is not None and dur < 0.25 * n * SUSPEND * 1000
        else:
            dok = dur is not None and dur >= 0.9 * n * SUSPEND * 1000
        report.append("%s: %d clients suspending %dms on %d threads: %ss, workers held %s, "
                      "all ok: %s; ExtendedStatus' Total Duration +%sms (suspended %dms in "
                      "all): %s" % (mode, n, SUSPEND * 1000, THREADS, t, busy, verdict(ok),
                                    dur, n * SUSPEND * 1000, verdict(dok)))

        wait_idle()
        n = 32 if is_async else THREADS
        smp = Sampler([SUSPEND / 2, SUSPEND + BACKEND_MS / 2000.0])
        res, t = parallel(n, lambda i: get("/p/x?d=%d&i=%d" % (BACKEND_MS, i)))
        busy = smp.held()
        ok = all(r[0] == 200 and len(r[1]) == 512 for r in res)
        if is_async:
            ok = ok and busy is not None and busy <= 1 and t < 3 * (SUSPEND + BACKEND_MS / 1000)
        report.append("%s: %d clients suspending %dms then proxied (backend %dms): %ss, "
                      "workers held %s, all ok: %s"
                      % (mode, n, SUSPEND * 1000, BACKEND_MS, t, busy, verdict(ok)))

        # A resume before the handler returned SUSPENDED: refused (logged),
        # one response; a debug build asserts (the child aborts, the server
        # serves again with a new one)
        before = log()
        refused0 = before.count("resumed while not suspended")
        crashes0 = before.count("exit signal")
        st, body, hdr = get("/twice/x", timeout=10)
        time.sleep(0.2)
        after = log()
        refused = after.count("resumed while not suspended") - refused0
        aborted = after.count("exit signal") - crashes0
        if not is_async:
            ok = st == 200 and body == b"aptest-suspend1: ok\n" and refused == 0
            what = "no early resume when blocking"
        elif DEBUG:
            ok = refused == 1 and aborted == 1 and st != 200 and serving(10)
            what = "debug build: refused, asserted (child aborted), serving again"
        else:
            ok = st == 200 and body == b"aptest-suspend1: ok\n" and refused == 1 and not aborted
            what = "refused, one response"
        report.append("%s: twice (%s): %s %s, refusals logged %d, child aborts %d: %s"
                      % (mode, what, st, short(body)[:40], refused, aborted, verdict(ok)))
        expected_aborts = 1 if is_async and DEBUG else 0

        text = log()
        findings = {
            "refused resumes": text.count("resumed while not suspended"),
            "resumed with SUSPENDED": text.count("resumed with SUSPENDED"),
            "abandoned": text.count("abandoned by its continuation"),
            "interrupted": text.count("waiting interrupted"),
            "crashes": text.count("exit signal") - expected_aborts,
            "errors": sum(1 for l in text.splitlines()
                          if (":error]" in l or ":crit]" in l or ":emerg]" in l)
                          and "resumed while not suspended" not in l
                          and "MaxRequestWorkers" not in l
                          and not (expected_aborts and "assertion" in l.lower())),
        }
        report.append("%s: error_log: %s: %s"
                      % (mode, findings, verdict(findings["crashes"] == 0
                                                 and findings["errors"] == 0
                                                 and findings["abandoned"] == 0)))

        # Graceful stop during suspensions of 5s (as many as the threads when
        # blocking): they complete, no hang
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
        crashes = log().count("exit signal") - expected_aborts
        ok = t is not None and t < 8 and not crashes
        report.append("%s: graceful stop during %d suspensions of 5s: stopped after %ss, "
                      "statuses %s, crashes %d: %s"
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
