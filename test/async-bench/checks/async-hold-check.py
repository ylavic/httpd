"""Check request filters holding their output or input (ap_filter_pending_wait())
through mod_aptest's holding filters ("AptestHold"): a static file's EOS held
on a timer and on a notifier by many clients on few threads, then by two
filters of a request in turn, each on a notifier of its own, a proxied
response streamed through a filter holding each chunk (the producer backing
off), a large response passed in pieces held for room to a crawling reader,
ap_die()'s error response held by a protocol filter (the request's second
hold point), a request body held by an input filter while the handler (the
core's body reader, and mod_proxy streaming it to a backend) waits for the
client: its wait completes when the hold does, though nothing more comes on
the socket; a hold refused while a subrequest of the request writes through
the filter, pipelined requests answered in order, a hold longer than the
server's Timeout (given up, the connection closed), a graceful stop while
holding, the same over TLS, and no error line of the core's held output
invariants. "sync" runs them with AsyncRequests Off (every hold refused, the
filter sleeping instead: the same bytes, the threads held), "async" with the
holds waiting in the MPM: the workers held (mod_status' BusyWorkers, but the
status request's own) and the times are checked there.

mod_aptest is built from ../../pyhttpd/mod_aptest with the install's apxs
into WORKDIR unless MOD_APTEST_SO is given; the Go backend (../backend) must
be built.

usage: MODES="sync async" python3 -I async-hold-check.py HTTPD_PREFIX [MOD_APTEST_SO] WORKDIR
"""

import hashlib
import http.client
import os
import re
import shutil
import signal
import socket
import ssl
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
PORT, TLSPORT, BACKEND = 18460, 18461, 18462
THREADS = 4
TIMEOUT = 2       # Timeout (s)
HOLD = 0.4        # the holds at the EOS (s)
GRACE_HOLD = 1.5  # the holds pending at a graceful stop (s), under Timeout
CHUNK_HOLD = 0.05 # each chunk's hold (s)
FILE_SIZE = 100000
BIG_SIZE = 1 << 20

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

cert, key = os.path.join(work, "cert.pem"), os.path.join(work, "key.pem")
if not os.path.exists(cert):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=127.0.0.1"],
                   check=True, capture_output=True)

docs = os.path.join(work, "docs")
FILES = {
    "file.txt": bytes([65 + i % 26 for i in range(FILE_SIZE)]),
    "big.bin": bytes([(i * 7) % 251 for i in range(BIG_SIZE)]),
}
# The files, at the top and under each holding location
for d in ("", "timer", "notifier", "twice", "long", "grace", "room", "proto"):
    os.makedirs(os.path.join(docs, d), exist_ok=True)
    for name, data in FILES.items():
        with open(os.path.join(docs, d, name), "wb") as f:
            f.write(data)

backend = subprocess.Popen([os.path.join(here, "..", "backend"),
                            "-addr", "127.0.0.1:%d" % BACKEND])

# A streamed backend response: several reads (chunks) per request
STREAM_SIZE, STREAM = 65536, "s=65536&c=8192&i=10000"

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{port}
Listen 127.0.0.1:{tlsport}
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
LoadModule ssl_module modules/mod_ssl.so
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
Timeout {timeout}
KeepAliveTimeout 5
GracefulShutdownTimeout 3
AcceptFilter http none
AcceptFilter https none
EnableSendfile off
EnableMMAP off
SendBufferSize 16384
LogFormat "%r %>s %D" t
CustomLog "{work}/access_log" t
ProxyAsyncDelay 0
{modeconf}
<Location "/timer/">
    AptestHold timer {hold_ms}
</Location>
<Location "/notifier/">
    AptestHold notifier {hold_ms}
</Location>
<Location "/twice/">
    AptestHold notifier {hold_ms}
    SetOutputFilter APTEST_HOLD_PROTO
</Location>
<Location "/long/">
    AptestHold timer 5000
</Location>
<Location "/grace/">
    AptestHold timer {grace_ms}
</Location>
<Location "/proto/">
    AptestHold timer {hold_ms} proto
</Location>
<Location "/room/">
    AptestHold room 16384
</Location>
<Location "/chunk/">
    AptestHold chunk {chunk_ms}
    ProxyPass "http://127.0.0.1:{backend}/"
</Location>
<Location "/input/digest">
    SetHandler aptest-wait
    AptestWait digest
    AptestHold input {hold_ms}
</Location>
<Location "/input/proxy/">
    AptestHold input {hold_ms}
    ProxyPass "http://127.0.0.1:{backend}/"
</Location>
<Location "/subreq">
    SetHandler aptest-wait
    AptestWait timer 10
    AptestSubreq /file.txt 1 passed
    AptestHold chunk {chunk_ms}
</Location>
<Location "/server-status">
    SetHandler server-status
</Location>
<VirtualHost 127.0.0.1:{tlsport}>
    SSLEngine on
    SSLCertificateFile "{work}/cert.pem"
    SSLCertificateKeyFile "{work}/key.pem"
</VirtualHost>
"""
MODES = {"sync": "AsyncRequests Off", "async": ""}


def start(modeconf):
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(CONF.format(prefix=prefix, work=work, port=PORT, tlsport=TLSPORT,
                            backend=BACKEND, aptest=aptest, docs=docs, threads=THREADS,
                            timeout=TIMEOUT, hold_ms=int(HOLD * 1000),
                            grace_ms=int(GRACE_HOLD * 1000),
                            chunk_ms=int(CHUNK_HOLD * 1000), modeconf=modeconf))
    for name in ("error_log", "access_log"):
        open(os.path.join(work, name), "w").close()
    p = subprocess.Popen([os.path.join(prefix, "bin", "httpd"), "-f",
                          os.path.join(work, "httpd.conf"), "-DFOREGROUND"])
    for _ in range(100):
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


def get(path, port=PORT, timeout=30, tls=False):
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        c = http.client.HTTPSConnection("127.0.0.1", port, timeout=timeout, context=ctx)
    else:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        c.request("GET", path)
        r = c.getresponse()
        return r.status, r.read()
    except (http.client.HTTPException, OSError) as e:
        return type(e).__name__, b""
    finally:
        c.close()


def busy_workers():
    st, body = get("/server-status?auto", timeout=5)
    m = re.search(rb"BusyWorkers: (\d+)", body) if st == 200 else None
    return int(m.group(1)) if m else None


class Sampler:
    """BusyWorkers every `interval` from `after` on, in the background"""

    def __init__(self, after, n, interval):
        self.samples = []
        self.t = threading.Thread(target=self.run, args=(after, n, interval))
        self.t.start()

    def run(self, after, n, interval):
        time.sleep(after)
        for _ in range(n):
            self.samples.append(busy_workers())
            time.sleep(interval)

    def held(self):
        """the worst number of workers held besides the status request's,
        THREADS for a status request not answered"""
        self.t.join()
        return max(THREADS if b is None else b - 1 for b in self.samples)


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


def recv_response(s, slow=None):
    """read one response from s (slow: (bytes, pause) per read): status,
    headers, body (chunked decoded), and what's left after it"""
    data = b""
    while b"\r\n\r\n" not in data:
        b = s.recv(slow[0] if slow else 65536)
        if not b:
            return None, {}, b"", b""
        data += b
    head, _, buf = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split(b" ")[1])
    hdrs = {}
    for l in lines[1:]:
        k, _, v = l.partition(b":")
        hdrs[k.strip().lower()] = v.strip()
    chunked = hdrs.get(b"transfer-encoding") == b"chunked"
    while True:
        if b"content-length" in hdrs and len(buf) >= int(hdrs[b"content-length"]):
            n = int(hdrs[b"content-length"])
            return status, hdrs, buf[:n], buf[n:]
        if chunked and b"\r\n0\r\n\r\n" in b"\r\n" + buf:
            break
        if slow:
            time.sleep(slow[1])
        b = s.recv(slow[0] if slow else 65536)
        if not b:
            break
        buf += b
    if not chunked:
        return status, hdrs, buf, b""
    body = b""
    while buf:
        size, _, buf = buf.partition(b"\r\n")
        n = int(size.split(b";")[0], 16)
        if n == 0:
            buf = buf[2:]
            break
        body += buf[:n]
        buf = buf[n + 2:]
    return status, hdrs, body, buf


def digest_of(data):
    return b"%d %s" % (len(data), hashlib.md5(data).hexdigest().encode())


def verdict(ok):
    return "OK" if ok else "FAIL"


def errlog():
    with open(os.path.join(work, "error_log")) as f:
        return f.read()


def holds_logged(log, name):
    """the sums of the holds, refusals, sleeps and failed waits logged by the
    filter `name` (aptest-hold lines), and how many lines"""
    tot = [0, 0, 0, 0]
    n = 0
    for m in re.finditer(r"aptest-hold: '%s' filter: holds=(\d+) refused=(\d+) "
                         r"sleeps=(\d+) failed=(\d+)" % re.escape(name), log):
        n += 1
        for i in range(4):
            tot[i] += int(m.group(i + 1))
    return tot, n


# The core's held output invariants and crashes: none expected
INVARIANTS = ("hold output at the request's end", "hold output at an internal redirect",
              "holds again after its hold's wait failed", "exit signal")


report = []
for mode in os.environ.get("MODES", "sync async").split():
    p = start(MODES[mode])
    asyn = (mode == "async")
    try:
        # The EOS held on a timer, then on a notifier: 16 clients on 4 threads
        for kind in ("timer", "notifier"):
            n = 16
            log0 = len(errlog())
            sampler = Sampler(HOLD / 2, 3, HOLD / 8)
            res, t = parallel(n, lambda i: get("/%s/file.txt?i=%d" % (kind, i)))
            busy = sampler.held()
            time.sleep(0.2)
            tot, lines = holds_logged(errlog()[log0:], "aptest_hold")
            same = all(r == (200, FILES["file.txt"]) for r in res)
            if asyn:
                ok = same and t < HOLD * 2.5 and busy <= 1 and tot[0] == n and tot[1] == 0
            else:
                ok = same and t >= HOLD * n / THREADS * 0.9 and tot[1] == n and tot[2] == n
            report.append("%s: %d clients, the EOS held on a %s of %dms: %.2fs, workers held %s, "
                          "bodies %s, holds/refused/sleeps/failed %s: %s"
                          % (mode, n, kind, HOLD * 1000, t, busy,
                             "same" if same else "DIFFER", tot, verdict(ok)))

        # Two holding filters in one request, each on a notifier of its own
        # attached to the request's: the EOS held by one, then by the other
        # (8 clients: the sync ones queued for a worker stay under Timeout)
        n = 8
        log0 = len(errlog())
        sampler = Sampler(HOLD, 3, HOLD / 4)
        res, t = parallel(n, lambda i: get("/twice/file.txt?i=%d" % i))
        busy = sampler.held()
        time.sleep(0.2)
        log = errlog()[log0:]
        tot1, _ = holds_logged(log, "aptest_hold")
        tot2, _ = holds_logged(log, "aptest_hold_proto")
        same = all(r == (200, FILES["file.txt"]) for r in res)
        if asyn:
            ok = (same and t < HOLD * 4 and busy <= 1 and tot1[0] == n and tot2[0] == n
                  and tot1[1] == 0 and tot2[1] == 0 and tot1[3] == 0 and tot2[3] == 0)
        else:
            ok = (same and t >= 2 * HOLD * n / THREADS * 0.9 and tot1[2] == n
                  and tot2[2] == n)
        report.append("%s: %d clients, the EOS held by two filters on notifiers of %dms: %.2fs, "
                      "workers held %s, statuses %s, bodies %s, holds/refused/sleeps/failed %s and %s: %s"
                      % (mode, n, HOLD * 1000, t, busy, sorted(set(str(r[0]) for r in res)),
                         "same" if same else "DIFFER", tot1, tot2, verdict(ok)))

        # Each chunk of a proxied streamed response held (mid-stream holds)
        n = 8
        log0 = len(errlog())
        sampler = Sampler(0.3, 3, 0.1)
        res, t = parallel(n, lambda i: get("/chunk/?%s&i=%d" % (STREAM, i)))
        busy = sampler.held()
        time.sleep(0.2)
        tot, lines = holds_logged(errlog()[log0:], "aptest_hold")
        same = all(r[0] == 200 and len(r[1]) == STREAM_SIZE for r in res)
        ok = same and (busy <= 1 and tot[0] >= n and tot[1] == 0 if asyn
                       else tot[1] >= n and tot[0] == 0)
        report.append("%s: %d proxied streams (%d bytes, chunks held %dms each): %.2fs, "
                      "workers held %s, bodies %s, holds/refused/sleeps/failed %s: %s"
                      % (mode, n, STREAM_SIZE, CHUNK_HOLD * 1000, t, busy,
                         "ok" if same else "WRONG", tot, verdict(ok)))

        # A large response passed in pieces held for room, to crawling readers
        def crawl(i):
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
            s.settimeout(30)
            s.connect(("127.0.0.1", PORT))
            try:
                s.sendall(b"GET /room/big.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                st, _, body, _ = recv_response(s, slow=(65536, 0.01))
                return st, body == FILES["big.bin"]
            finally:
                s.close()
        n = 6
        log0 = len(errlog())
        sampler = Sampler(0.3, 3, 0.1)
        res, t = parallel(n, crawl)
        busy = sampler.held()
        time.sleep(0.2)
        tot, lines = holds_logged(errlog()[log0:], "aptest_hold")
        same = all(r == (200, True) for r in res)
        ok = same and (busy <= 1 and tot[0] > 0 if asyn else tot[0] == 0)
        report.append("%s: %d crawling readers of 1MB passed in 16KB pieces held for room: "
                      "%.2fs, workers held %s, bodies %s, holds/refused %s: %s"
                      % (mode, n, t, busy, "same" if same else "DIFFER", tot[:2], verdict(ok)))

        # ap_die()'s error response held by a protocol filter (second point)
        log0 = len(errlog())
        t0 = time.monotonic()
        st, body = get("/proto/missing.txt")
        t = round(time.monotonic() - t0, 2)
        time.sleep(0.2)
        tot, lines = holds_logged(errlog()[log0:], "aptest_hold_proto")
        ok = st == 404 and b"Not Found" in body and t >= HOLD * 0.9 and (
            tot[0] == 1 if asyn else tot[1] == 1)
        report.append("%s: a 404 held by a protocol filter (ap_die()'s response): %s in %.2fs, "
                      "holds/refused %s: %s" % (mode, st, t, tot[:2], verdict(ok)))

        # The request body held by an input filter while the handler waits for
        # the client: sent at once, nothing more comes on the socket
        data = bytes([97 + i % 26 for i in range(3000)])
        for path, want in (("/input/digest", None), ("/input/proxy/", 512)):
            n = 8
            log0 = len(errlog())

            def post(i):
                s = socket.create_connection(("127.0.0.1", PORT), timeout=30)
                try:
                    s.sendall(b"POST %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                              b"Content-Length: %d\r\n\r\n%s" % (path.encode(), len(data), data))
                    st, _, body, _ = recv_response(s)
                    return st, body
                finally:
                    s.close()
            sampler = Sampler(HOLD / 2, 3, HOLD / 8)
            res, t = parallel(n, post)
            busy = sampler.held()
            time.sleep(0.2)
            tot, lines = holds_logged(errlog()[log0:], "aptest_hold_in")
            if want is None:
                good = all(r[0] == 200 and r[1].startswith(digest_of(data)) for r in res)
            else:
                good = all(r[0] == 200 and len(r[1]) == want for r in res)
            ok = good and t < TIMEOUT and (busy <= 1 and tot[0] >= n if asyn
                                           else tot[1] >= n or tot[2] >= n)
            report.append("%s: %d bodies held %dms by an input filter (%s): %.2fs (Timeout %ds), "
                          "workers held %s, answers %s, holds/refused/sleeps %s: %s"
                          % (mode, n, HOLD * 1000, path, t, TIMEOUT, busy,
                             "ok" if good else "WRONG", tot[:3], verdict(ok)))

        # A subrequest writing through a filter: its holds refused (blocking)
        log0 = len(errlog())
        st, body = get("/subreq")
        time.sleep(0.2)
        tot, lines = holds_logged(errlog()[log0:], "aptest_hold")
        ok = st == 200 and body.startswith(FILES["file.txt"]) and tot[1] >= 1 and tot[2] >= 1
        report.append("%s: a subrequest passing through a holding filter: %s, %d bytes, "
                      "holds/refused/sleeps %s: %s" % (mode, st, len(body), tot[:3], verdict(ok)))

        # Pipelined requests on one connection, the first ones held: in order
        s = socket.create_connection(("127.0.0.1", PORT), timeout=30)
        try:
            s.sendall(b"".join(b"GET /timer/file.txt?p=%d HTTP/1.1\r\nHost: x\r\n\r\n" % i
                               for i in range(3))
                      + b"GET /file.txt?p=3 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            got, rest = [], b""
            t0 = time.monotonic()
            for i in range(4):
                # what's left from the previous read goes first
                class R:
                    def __init__(self, s, rest):
                        self.s, self.rest = s, rest

                    def recv(self, n):
                        if self.rest:
                            b, self.rest = self.rest, b""
                            return b
                        return self.s.recv(n)
                st, _, body, rest = recv_response(R(s, rest))
                got.append((st, body == FILES["file.txt"]))
            t = round(time.monotonic() - t0, 2)
        finally:
            s.close()
        ok = got == [(200, True)] * 4 and t >= HOLD * 3 * 0.9
        report.append("%s: 3 held responses pipelined before a plain one: %s in %.2fs: %s"
                      % (mode, got, t, verdict(ok)))

        # Over TLS (mod_ssl's front): the EOS held, a proxied stream held
        res, t = parallel(4, lambda i: get("/timer/file.txt?tls=%d" % i, port=TLSPORT, tls=True))
        ok1 = all(r == (200, FILES["file.txt"]) for r in res)
        res2, t2 = parallel(4, lambda i: get("/chunk/?%s&tls=%d" % (STREAM, i), port=TLSPORT,
                                             tls=True))
        ok2 = all(r[0] == 200 and len(r[1]) == STREAM_SIZE for r in res2)
        report.append("%s: TLS: 4 EOS held %.2fs, 4 proxied streams held %.2fs, bodies %s/%s: %s"
                      % (mode, t, t2, "same" if ok1 else "DIFFER",
                         "ok" if ok2 else "WRONG", verdict(ok1 and ok2)))

        # A hold longer than Timeout: given up at Timeout, the connection
        # closed (async); slept through (sync)
        log0 = len(errlog())
        t0 = time.monotonic()
        st, body = get("/long/file.txt", timeout=15)
        t = round(time.monotonic() - t0, 1)
        if asyn:
            ok = st != 200 and t < TIMEOUT + 1.5
        else:
            ok = st == 200 and body == FILES["file.txt"] and t >= 4.5
        report.append("%s: a 5s hold with Timeout %ds: %s, %d bytes in %ss: %s"
                      % (mode, TIMEOUT, st, len(body), t, verdict(ok)))

        log = errlog()
        bad = {k: log.count(k) for k in INVARIANTS if k in log}
        report.append("%s: error_log: invariants/crashes %s: %s"
                      % (mode, bad or "none", verdict(not bad)))

        # Graceful stop while 8 holds shorter than Timeout are pending
        # (GracefulShutdownTimeout 3): the holds complete and are answered
        # (async); the sync threads sleep through theirs, the requests queued
        # behind them may be cut
        res = [None] * 8

        def one(i):
            res[i] = get("/grace/file.txt?g=%d" % i, timeout=20)[0]
        ts = [threading.Thread(target=one, args=(i,)) for i in range(8)]
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
        crashes = errlog().count("exit signal")
        ok = t is not None and t < 8 and not crashes
        if asyn:
            ok = ok and res == [200] * 8 and t < TIMEOUT + 1
        report.append("%s: graceful stop during 8 holds of %.1fs (Timeout %ds): stopped after "
                      "%ss, statuses %s, crashes %d: %s"
                      % (mode, GRACE_HOLD, TIMEOUT, t, sorted(set(map(str, res))), crashes,
                         verdict(ok)))
    finally:
        report.append("%s: %s" % (mode, stop(p)))
        os.replace(os.path.join(work, "error_log"), os.path.join(work, "error_log." + mode))
backend.terminate()
backend.wait(5)
print("\n".join(report))
