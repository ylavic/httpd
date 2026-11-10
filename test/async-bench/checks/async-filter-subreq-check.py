"""Check request filters delegating their holds to subrequests
(ap_filter_pending_wait() with AP_FILTER_HOLD_DELEGATED, then
ap_run_sub_req_async()) through mod_aptest's "AptestFilterSubreq" filter,
which runs n subrequests in turn at the EOS of a response (or mid-stream,
before the first data of a proxied stream, the producer paused meanwhile),
their output captured or passed below the filter, then passes what it held
with a summary line: proxied subrequests waiting for a delayed backend (1, 3
and 8 in turn, the next one run when the core calls the filter again), many
clients on few threads, a subrequest reaching its timeout (504 to the
filter), the work's timeout bounding the request's end rather than Timeout
(a subrequest whose own timeout is longer than Timeout completing past it,
one without a timeout getting Timeout: 504 to the filter), ap_die()'s
error response held by a protocol filter running a subrequest (the
request's second hold point), the refusals run blocking with the same
output (a subrequest's own filter, AsyncRequests Off), the core's checks of
misuses (a filter running ap_run_sub_req_async() without a delegated hold:
run blocking, logged; a delegated hold without its work: released, logged),
pipelined requests answered in order, a client closing while its delegated
subrequest waits for a connection from an exhausted pool (async: served
once a connection is released, the server going on, the pool serving a next
request at once: the waiter's cleanup at the request's end gives nothing back
twice), a graceful stop during delegated subrequests, and no error line of
the core's held output invariants.
"sync" runs them with AsyncRequests Off (every hold refused, the
subrequests blocking: the same responses, the threads held), "async" with
the subrequests' waits in the MPM: the workers held (mod_status'
BusyWorkers, but the status request's own) and the times are checked
there.

mod_aptest is built from ../../pyhttpd/mod_aptest with the install's apxs
into WORKDIR unless MOD_APTEST_SO is given; the Go backend (../backend) must
be built.

usage: MODES="sync async" python3 -I async-filter-subreq-check.py HTTPD_PREFIX [MOD_APTEST_SO] WORKDIR
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
PORT, BACKEND = 18465, 18466
THREADS = 4
BACKEND_MS = 100        # the proxied subrequests' backend delay
TIMEOUT_MS = 300        # the subrequests' timeout of the timeout case
SERVER_TIMEOUT = 5      # Timeout
LONG_MS = 6500          # a backend delay longer than Timeout
LONG_TIMEOUT_MS = 8000  # a subrequest's own timeout longer than that
NONE_MS = 8000          # a backend not answering within Timeout

if not aptest:
    src = os.path.join(here, "..", "..", "pyhttpd", "mod_aptest", "mod_aptest.c")
    bdir = os.path.join(work, "aptest")
    os.makedirs(bdir, exist_ok=True)
    shutil.copy(src, bdir)
    r = subprocess.run([os.path.join(prefix, "bin", "apxs"), "-c", "mod_aptest.c"],
                       cwd=bdir, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("building mod_aptest failed:\n" + r.stdout + r.stderr)
    aptest = os.path.join(bdir, ".libs", "mod_aptest.so")

LOCATIONS = ("fe1", "fe3", "fe8", "fb3", "fto", "ftolong", "ftonone", "fproto",
             "fnohold", "funpaired", "flong", "fpool")
POOL_HOLD_MS = 2000     # how long the only connection of /pm/'s pool is taken
FILE = b"".join(b"line %04d of the file\n" % i for i in range(200))
docs = os.path.join(work, "htdocs")
for d in ("",) + LOCATIONS:
    os.makedirs(os.path.join(docs, d), exist_ok=True)
    with open(os.path.join(docs, d, "file.txt"), "wb") as f:
        f.write(FILE)

backend = subprocess.Popen([os.path.join(here, "..", "backend"),
                            "-addr", "127.0.0.1:%d" % BACKEND])

# A streamed backend response: several reads per request, the producer of
# the mid-stream case, and the 8 subrequests' (their backend descriptor kept)
STREAM_SIZE, STREAM = 65536, "s=65536&c=4096&i=20000"

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{port}
PidFile "{work}/httpd.pid"
ErrorLog "{work}/error_log"
LogLevel warn aptest:info
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule status_module modules/mod_status.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule aptest_module {aptest}
ServerName localhost
DocumentRoot "{docs}"
StartServers 1
ServerLimit 1
ThreadLimit {threads}
ThreadsPerChild {threads}
MaxRequestWorkers {threads}
MinSpareThreads 1
MaxSpareThreads {threads}
AsyncAdmissionBacklogPerThread 64
Timeout {server_timeout}
KeepAliveTimeout 5
GracefulShutdownTimeout 5
AcceptFilter http none
EnableSendfile off
EnableMMAP off
LogFormat "%r %>s %D" t
CustomLog "{work}/access_log" t
ProxyAsyncDelay 0
ProxyTimeout 10
{modeconf}
ProxyPass "/p/" "http://127.0.0.1:{backend}/p/"
ProxyPass "/pm/" "http://127.0.0.1:{backend}/pm/" max=1
<Location "/fe1/">
    AptestFilterSubreq "/p/x?d={backend_ms}" 1 captured
</Location>
<Location "/fe3/">
    AptestFilterSubreq "/p/x?d={backend_ms}" 3 captured
</Location>
<Location "/fe8/">
    AptestFilterSubreq "/p/x?{stream}" 8 captured
</Location>
<Location "/fb3/">
    AptestFilterSubreq "/p/x?d={backend_ms}" 3 below
</Location>
<Location "/fmid/">
    AptestFilterSubreq "/p/x?d={backend_ms}" 3 captured mid
    ProxyPass "http://127.0.0.1:{backend}/"
</Location>
<Location "/fto/">
    AptestFilterSubreq "/p/x?d=2000" 1 captured timeout {timeout_ms}
</Location>
<Location "/ftolong/">
    AptestFilterSubreq "/p/x?d={long_ms}" 1 captured timeout {long_timeout_ms}
</Location>
<Location "/ftonone/">
    AptestFilterSubreq "/p/x?d={none_ms}" 1 captured
</Location>
<Location "/fproto/">
    AptestFilterSubreq "/p/x?d={backend_ms}" 1 captured proto
</Location>
<Location "/fsr/">
    AptestSubreq "/fe1/file.txt" 1 passed
</Location>
<Location "/fnohold/">
    AptestFilterSubreq "/p/x?d={backend_ms}" 2 captured nohold
</Location>
<Location "/funpaired/">
    AptestFilterSubreq "/p/x?d={backend_ms}" 1 captured unpaired
</Location>
<Location "/fpool/">
    AptestFilterSubreq "/pm/x?d={backend_ms}" 1 captured
</Location>
<Location "/flong/">
    AptestFilterSubreq "/p/x?d=3000" 1 captured
</Location>
<Location "/server-status">
    SetHandler server-status
</Location>
"""
MODES = {"sync": "AsyncRequests Off", "async": ""}


def start(modeconf):
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(CONF.format(prefix=prefix, work=work, port=PORT, backend=BACKEND,
                            aptest=aptest, docs=docs, threads=THREADS,
                            backend_ms=BACKEND_MS, timeout_ms=TIMEOUT_MS,
                            server_timeout=SERVER_TIMEOUT, long_ms=LONG_MS,
                            long_timeout_ms=LONG_TIMEOUT_MS, none_ms=NONE_MS,
                            stream=STREAM, modeconf=modeconf))
    for name in ("error_log", "access_log"):
        open(os.path.join(work, name), "w").close()
    p = subprocess.Popen([os.path.join(prefix, "bin", "httpd"), "-f",
                          os.path.join(work, "httpd.conf"), "-DFOREGROUND"])
    t0 = time.monotonic()
    while time.monotonic() - t0 < 10:
        try:
            c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=1)
            c.request("GET", "/nothing")
            c.getresponse().read()
            c.close()
            return p
        except OSError:
            time.sleep(0.05)
    stop(p)
    raise SystemExit("httpd didn't start")


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
    """status, body, the time taken"""
    t0 = time.monotonic()
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    try:
        c.request("GET", path)
        r = c.getresponse()
        return r.status, r.read(), round(time.monotonic() - t0, 2)
    except (http.client.HTTPException, OSError) as e:
        return type(e).__name__, b"", round(time.monotonic() - t0, 2)
    finally:
        c.close()


def busy_workers():
    st, body, _ = get("/server-status?auto", timeout=5)
    m = re.search(rb"BusyWorkers: (\d+)", body) if st == 200 else None
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


def filter_logged(text, name="aptest_fsubreq"):
    """the sums of the holds, subrequests suspended, ended at once and holds
    refused logged by the filter `name`, its lines' statuses, and how many
    lines"""
    tot = [0, 0, 0, 0, 0]
    statuses = []
    n = 0
    for m in re.finditer(r"aptest-fsubreq: '%s' filter: holds=(\d+) async=(\d+) "
                         r"inline=(\d+) refused=(\d+) unpaired=(\d+) n=\d+ "
                         r"statuses=(\S*)" % re.escape(name), text):
        n += 1
        for i in range(5):
            tot[i] += int(m.group(i + 1))
        statuses.append(m.group(6))
    return tot, statuses, n


def summary_line(n, statuses, captured=None):
    line = b"aptest-fsubreq: n=%d statuses=%s" % (n, statuses.encode())
    if captured is not None:
        line += b" captured=%d:%s" % (len(captured),
                                      hashlib.md5(captured).hexdigest()[:8].encode())
    return line + b"\n"


# The core's held output invariants, delegated holds' abandons, crashes: none
INVARIANTS = ("hold output at the request's end", "hold output at an internal redirect",
              "holds again after its hold's wait failed", "abandoning the subrequest",
              "suspended without a delegated hold", "exit signal")
NOHOLD_LINE = "from a filter without a delegated hold"
UNPAIRED_LINE = "returned without the work its delegated hold was for"

report = []
responses = {}   # mode -> case -> (status, body md5)
BACKEND_BODY = None
for mode in os.environ.get("MODES", "sync async").split():
    is_async = mode == "async"
    resp = responses[mode] = {}
    p = start(MODES[mode])
    try:
        if BACKEND_BODY is None:
            st, BACKEND_BODY, _ = get("/p/x")
            if st != 200 or len(BACKEND_BODY) != 512:
                raise SystemExit("backend not answering: %s" % short(BACKEND_BODY))

        def case(name, st, body, ok, extra="", compare=True):
            if compare:
                resp[name] = (st, hashlib.md5(body).hexdigest()[:8])
            report.append("%s: %s: %s, %d bytes%s: %s" % (mode, name, st, len(body),
                                                         extra, verdict(ok)))

        def counts_ok(tot, n_holds, n_async=None):
            """holds and subrequests suspended in async, refused in sync"""
            if is_async:
                return tot[0] == n_holds and tot[1] == (n_holds if n_async is None
                                                        else n_async) and tot[3] == 0
            return tot[0] == 0 and tot[1] == 0 and tot[3] == n_holds

        # At the EOS of a static file: 1, 3 and 8 subrequests in turn,
        # captured (8 streamed: their backend's descriptor kept by the MPM)
        for loc, n, query, body1 in (("fe1", 1, "d=%d" % BACKEND_MS, BACKEND_BODY),
                                     ("fe3", 3, "d=%d" % BACKEND_MS, BACKEND_BODY),
                                     ("fe8", 8, STREAM, b"x" * STREAM_SIZE)):
            log0 = len(log())
            st, body, t = get("/%s/file.txt" % loc)
            time.sleep(0.1)
            tot, sts, _ = filter_logged(log()[log0:])
            want = FILE + summary_line(n, ",".join(["200"] * n), body1 * n)
            ok = st == 200 and body == want and counts_ok(tot, n)
            case("%d subrequest(s) at the EOS, captured" % n, st, body, ok,
                 " in %ss, holds/async/inline/refused %s" % (t, tot[:4]))

        # Passed below the filter (as mod_include's), before what it held
        log0 = len(log())
        st, body, t = get("/fb3/file.txt")
        time.sleep(0.1)
        tot, sts, _ = filter_logged(log()[log0:])
        want = BACKEND_BODY * 3 + FILE + summary_line(3, "200,200,200")
        ok = st == 200 and body == want and counts_ok(tot, 3)
        case("3 subrequests at the EOS, passed below", st, body, ok,
             " in %ss, holds/async/inline/refused %s" % (t, tot[:4]))

        # Mid-stream: before the first data of a proxied stream, its producer
        # paused meanwhile; 8 clients on 4 threads
        wait_idle()
        n = 8 if is_async else THREADS
        log0 = len(log())
        smp = Sampler([0.15, 0.25])
        res, t = parallel(n, lambda i: get("/fmid/?%s&i=%d" % (STREAM, i)))
        busy = smp.held()
        time.sleep(0.1)
        tot, sts, lines = filter_logged(log()[log0:])
        want = b"x" * STREAM_SIZE + summary_line(3, "200,200,200", BACKEND_BODY * 3)
        good = all(r[0] == 200 and r[1] == want for r in res)
        ok = good and lines == n and counts_ok(tot, 3 * n)
        if is_async:
            ok = ok and busy is not None and busy <= 1
        resp["mid-stream"] = (good,)
        report.append("%s: %d proxied streams, 3 subrequests mid-stream each: %ss, workers "
                      "held %s, bodies %s, holds/async/inline/refused %s: %s"
                      % (mode, n, t, busy, "ok" if good else "WRONG", tot[:4], verdict(ok)))

        # Many clients at once on THREADS threads (as many as don't wait for
        # a worker longer than Timeout when blocking)
        wait_idle()
        n = 16 if is_async else THREADS
        smp = Sampler([BACKEND_MS / 2000.0, 1.5 * BACKEND_MS / 1000.0,
                       2.5 * BACKEND_MS / 1000.0])
        res, t = parallel(n, lambda i: get("/fe3/file.txt?i=%d" % i))
        busy = smp.held()
        want = FILE + summary_line(3, "200,200,200", BACKEND_BODY * 3)
        ok = all(r[0] == 200 and r[1] == want for r in res)
        if is_async:
            ok = ok and busy is not None and busy <= 1 and t < 10 * 3 * BACKEND_MS / 1000
        report.append("%s: %d clients, 3 subrequests at the EOS each (backend %dms) on %d "
                      "threads: %ss, workers held %s, all ok: %s"
                      % (mode, n, BACKEND_MS, THREADS, t, busy, verdict(ok)))

        # A subrequest over its timeout: 504 to the filter (async), no
        # deadline when blocking (sync)
        st, body, t = get("/fto/file.txt")
        if is_async:
            ok = st == 200 and body == FILE + summary_line(1, "504", b"") and t < 1.5
        else:
            ok = st == 200 and body == FILE + summary_line(1, "200", BACKEND_BODY) and t >= 2
        case("a subrequest over its timeout (%dms, backend 2000ms)" % TIMEOUT_MS, st, body,
             ok, " in %ss, %s" % (t, body[len(FILE):].strip()[:60]), compare=False)

        # The work's own timeout bounds the request's end waiting for the
        # delegated hold, not Timeout: a subrequest whose timeout is longer
        # than Timeout completes past it (blocking: the same, no deadline)
        st, body, t = get("/ftolong/file.txt")
        ok = (st == 200 and body == FILE + summary_line(1, "200", BACKEND_BODY)
              and LONG_MS / 1000 <= t < LONG_MS / 1000 + 1.5)
        case("a subrequest with its own timeout (%dms) longer than Timeout (%ds), "
             "backend %dms" % (LONG_TIMEOUT_MS, SERVER_TIMEOUT, LONG_MS), st, body, ok,
             " in %ss, %s" % (t, body[len(FILE):].strip()[:60]), compare=False)

        # A subrequest without a timeout gets Timeout (async): 504 to the
        # filter at about Timeout; no deadline when blocking (sync)
        st, body, t = get("/ftonone/file.txt")
        if is_async:
            ok = (st == 200 and body == FILE + summary_line(1, "504", b"")
                  and SERVER_TIMEOUT - 0.2 <= t < SERVER_TIMEOUT + 1.5)
        else:
            ok = (st == 200 and body == FILE + summary_line(1, "200", BACKEND_BODY)
                  and t >= NONE_MS / 1000)
        case("a subrequest without a timeout, backend %dms, Timeout %ds"
             % (NONE_MS, SERVER_TIMEOUT), st, body, ok,
             " in %ss, %s" % (t, body[len(FILE):].strip()[:60]), compare=False)

        # ap_die()'s 404 held by a protocol filter running a subrequest (the
        # second hold point)
        log0 = len(log())
        st, body, t = get("/fproto/missing.txt")
        time.sleep(0.1)
        tot, sts, _ = filter_logged(log()[log0:], "aptest_fsubreq_proto")
        ok = (st == 404 and b"Not Found" in body and t >= BACKEND_MS / 1000 * 0.9
              and sts == ["200"] and counts_ok(tot, 1))
        case("a 404 held by a protocol filter running a subrequest", st, body, ok,
             " in %ss, holds/async/inline/refused %s, statuses %s" % (t, tot[:4], sts))

        # Refused for a subrequest's filter: blocking, the same output
        log0 = len(log())
        st, body, t = get("/fsr/x")
        time.sleep(0.1)
        tot, sts, _ = filter_logged(log()[log0:])
        want = FILE + summary_line(1, "200", BACKEND_BODY)
        ok = (st == 200 and body.startswith(want) and b"aptest-subreq: " in body
              and tot[0] == 0 and tot[3] == 1 and sts == ["200"])
        case("a subrequest's own filter (refused, blocking)", st,
             re.sub(rb"async=\d+", b"", body), ok,
             " holds/async/inline/refused %s" % tot[:4])

        # Misuses: ap_run_sub_req_async() without a delegated hold (run
        # blocking, logged), a delegated hold without its work (released,
        # logged)
        nohold0, unpaired0 = log().count(NOHOLD_LINE), log().count(UNPAIRED_LINE)
        st, body, t = get("/fnohold/file.txt")
        nohold = log().count(NOHOLD_LINE) - nohold0
        ok = (st == 200 and body == FILE + summary_line(2, "200,200", BACKEND_BODY * 2)
              and nohold == (2 if is_async else 0))
        case("ap_run_sub_req_async() from a filter without a delegated hold", st, body, ok,
             " in %ss, logged %d" % (t, nohold))
        log0 = len(log())
        st, body, t = get("/funpaired/file.txt")
        time.sleep(0.1)
        unpaired = log().count(UNPAIRED_LINE) - unpaired0
        tot, sts, _ = filter_logged(log()[log0:])
        ok = (st == 200 and body == FILE + summary_line(1, "200", BACKEND_BODY)
              and unpaired == (1 if is_async else 0) and tot[4] == (1 if is_async else 0))
        case("a delegated hold without its work", st, body, ok,
             " in %ss, logged %d" % (t, unpaired))

        # Pipelined, some delegating, in order
        res = pipelined(["/fe1/file.txt?1", "/fe3/file.txt?2", "/fb3/file.txt?3",
                         "/file.txt?4"])
        ok = (len(res) == 4 and None not in res
              and res[0] == (200, FILE + summary_line(1, "200", BACKEND_BODY))
              and res[1] == (200, FILE + summary_line(3, "200,200,200", BACKEND_BODY * 3))
              and res[2] == (200, BACKEND_BODY * 3 + FILE + summary_line(3, "200,200,200"))
              and res[3] == (200, FILE))
        report.append("%s: 4 pipelined requests, 3 delegating, in order: %s: %s"
                      % (mode, [r[0] if r else None for r in res], verdict(ok)))

        # A client closing while its delegated subrequest waits for the only
        # connection of an exhausted pool (/pm/, max=1): the server goes on,
        # and once the connection is released the pool serves a next request
        # at once (nothing kept nor given back twice for the gone request's
        # waiter)
        if is_async:
            wait_idle()
            taker = threading.Thread(target=lambda: get("/pm/x?d=%d" % POOL_HOLD_MS))
            taker.start()
            time.sleep(0.2)
            s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
            s.sendall(b"GET /fpool/file.txt HTTP/1.1\r\nHost: x\r\n\r\n")
            time.sleep(0.3)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\1\0\0\0\0\0\0\0")
            s.close()
            taker.join()
            time.sleep(0.2)
            st, body, t = get("/pm/x", timeout=10)
            alive = get("/file.txt", timeout=5)[0]
            crashes = log().count("exit signal")
            ok = st == 200 and t < 1 and alive == 200 and not crashes
            report.append("%s: a client closing while its subrequest waits for an exhausted "
                          "pool: next request through the pool %s in %ss, server %s, "
                          "crashes %d: %s" % (mode, st, t, alive, crashes, verdict(ok)))

        text = log()
        findings = {k: text.count(k) for k in INVARIANTS if k in text}
        errors = [l for l in text.splitlines()
                  if (":error]" in l or ":crit]" in l or ":emerg]" in l)
                  and NOHOLD_LINE not in l and UNPAIRED_LINE not in l
                  and "MaxRequestWorkers" not in l]
        # mod_proxy's own error for the timeout case's backend, expected
        errors = [l for l in errors if "timeout waiting for the response" not in l]
        report.append("%s: error_log: invariants/abandons/crashes %s, other errors %d%s: %s"
                      % (mode, findings or "none", len(errors),
                         " (%s)" % short(errors[0]) if errors else "",
                         verdict(not findings and not errors)))

        # Graceful stop during subrequests waiting 3s for the backend (as
        # many as the threads when blocking)
        n = 8 if is_async else THREADS
        res = [None] * n

        def one(i):
            res[i] = get("/flong/file.txt?i=%d" % i, timeout=20)[0]
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
        ok = t is not None and t < 8 and not crashes
        report.append("%s: graceful stop during %d delegated subrequests waiting 3s: stopped "
                      "after %ss, statuses %s, crashes %d: %s"
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
