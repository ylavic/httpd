"""Check the core's request body reader (ap_request_read_body(),
ap_request_wait_body(), ap_request_body_run(), ap_request_discard_body())
through mod_aptest's "aptest-body" handler and AptestSuspend's "read": bodies
by Content-Length and chunked, small and 8MB, read by a pull loop and by a
sink (digests), crawling uploads on few threads, chunked uploads whose
trailers trickle, Expect: 100-continue (the 100 sent without blocking),
LimitRequestBody (413 by Content-Length and mid-body), the read timeouts
(Timeout: the reader's 408, RequestReadTimeout body=: mod_reqtimeout's), a
malformed chunk (400), a TLS upload cut in a record, clients aborting
mid-upload, the discard (a small leftover keeping the connection, over the
limit by Content-Length or chunked, a 100 Continue never sent), a body read
then replayed by an input filter to mod_proxy_http, mod_proxy_scgi and
mod_proxy_uwsgi (r->read_length left alone), blocking reads from an output
filter while the request could suspend (AP_REQUEST_BODY_BLOCK), the error
log, and stops during uploads (graceful: they may complete; immediate:
closed, no hang: mpm_event closes the suspended connections without
completing their waits). "sync" runs them with AsyncRequests
Off (the reads block: the same results, the threads held), "async" with the
waits in the MPM (no thread held while waiting, checked with mod_status).

mod_aptest is built from ../../pyhttpd/mod_aptest with the install's apxs
into WORKDIR unless MOD_APTEST_SO is given; schemebackend (../schemebackend)
answers the scgi and uwsgi requests.

usage: MODES="sync async" python3 -I async-reqbody-check.py HTTPD_PREFIX [MOD_APTEST_SO] WORKDIR
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
PORT, RTPORT, TLSPORT, BPORT = 18449, 18450, 18451, 18452
SCGI, UWSGI = 18453, 18454
THREADS = 4
TIMEOUT = 2             # Timeout (s)
LIMIT = 100000          # LimitRequestBody of /limited/, AptestBody discard's

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

docs = os.path.join(work, "htdocs")
os.makedirs(os.path.join(docs, "s"), exist_ok=True)
with open(os.path.join(docs, "s", "file.txt"), "wb") as f:
    f.write(b"static file\n")

backend = subprocess.Popen([os.path.join(here, "..", "schemebackend"),
                            "-scgi=127.0.0.1:%d" % SCGI, "-uwsgi=127.0.0.1:%d" % UWSGI])

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{port}
Listen 127.0.0.1:{rtport}
Listen 127.0.0.1:{tlsport}
Listen 127.0.0.1:{bport}
PidFile "{work}/httpd.pid"
ErrorLog "{work}/error_log"
LogLevel warn aptest:trace5 http:info mpm_event:debug
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule status_module modules/mod_status.so
LoadModule reqtimeout_module modules/mod_reqtimeout.so
LoadModule ssl_module modules/mod_ssl.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule proxy_scgi_module modules/mod_proxy_scgi.so
LoadModule proxy_uwsgi_module modules/mod_proxy_uwsgi.so
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
Timeout {timeout}
KeepAliveTimeout 5
GracefulShutdownTimeout 3
# Silent clients reach httpd at once (no TCP_DEFER_ACCEPT)
AcceptFilter http none
AcceptFilter https none
RequestReadTimeout handshake=0 header=20 body=0
LogFormat "%r %>s %D" t
CustomLog "{work}/access_log" t
{modeconf}
ProxyPass "/rp/" "http://127.0.0.1:{bport}/pull/"
ProxyPass "/rs/" "scgi://127.0.0.1:{scgi}/rs/"
ProxyPass "/ru/" "uwsgi://127.0.0.1:{uwsgi}/ru/"
<Location "/pull">
    SetHandler aptest-body
    AptestBody pull
</Location>
<Location "/sink">
    SetHandler aptest-body
    AptestBody sink
</Location>
<Location "/pullblock">
    SetHandler aptest-body
    AptestBody pull block
</Location>
<Location "/sinkblock">
    SetHandler aptest-body
    AptestBody sink block
</Location>
<Location "/limited">
    SetHandler aptest-body
    AptestBody pull
    LimitRequestBody {limit}
</Location>
<Location "/discard">
    SetHandler aptest-body
    AptestBody discard {limit}
</Location>
<Location "/rp/">
    AptestSuspend 10 declined read
</Location>
<Location "/rs/">
    AptestSuspend 10 declined read
</Location>
<Location "/ru/">
    AptestSuspend 10 declined read
</Location>
<Location "/server-status">
    SetHandler server-status
</Location>
<VirtualHost 127.0.0.1:{rtport}>
    Timeout 10
    RequestReadTimeout handshake=0 header=20 body=2
</VirtualHost>
<VirtualHost 127.0.0.1:{tlsport}>
    SSLEngine on
    SSLCertificateFile "{work}/cert.pem"
    SSLCertificateKeyFile "{work}/key.pem"
</VirtualHost>
"""
MODES = {"sync": "AsyncRequests Off", "async": ""}


def start(modeconf):
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(CONF.format(prefix=prefix, work=work, port=PORT, rtport=RTPORT,
                            tlsport=TLSPORT, bport=BPORT, scgi=SCGI, uwsgi=UWSGI,
                            aptest=aptest, threads=THREADS, timeout=TIMEOUT,
                            limit=LIMIT, modeconf=modeconf))
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
            c.request("GET", "/s/file.txt")
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


def get(path, port=PORT, timeout=30):
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
    """fn(i) for i in range(n) at once (threads): the results, the time"""
    res = [None] * n

    def one(i):
        try:
            res[i] = fn(i)
        except Exception as e:  # report it, as a result
            res[i] = ("EXC", type(e).__name__, b"")
    t0 = time.monotonic()
    ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return res, round(time.monotonic() - t0, 2)


def recv_head(s, buf=b""):
    """a response head from s: status, headers (lowercase names), the rest"""
    while b"\r\n\r\n" not in buf:
        b = s.recv(65536)
        if not b:
            return None, {}, buf
        buf += b
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split(b" ")[1])
    hdrs = {}
    for l in lines[1:]:
        k, _, v = l.partition(b":")
        hdrs[k.strip().lower()] = v.strip()
    return status, hdrs, rest


def recv_response(s, buf=b""):
    """a whole response from s: status, headers, body (chunked decoded),
    what follows it"""
    status, hdrs, buf = recv_head(s, buf)
    if status is None:
        return None, {}, b"", b""
    if hdrs.get(b"transfer-encoding") == b"chunked":
        body = b""
        while True:
            while b"\r\n" not in buf:
                b = s.recv(65536)
                if not b:
                    return status, hdrs, body, b""
                buf += b
            size, _, buf = buf.partition(b"\r\n")
            n = int(size.split(b";")[0], 16)
            while len(buf) < n + 2:
                b = s.recv(65536)
                if not b:
                    return status, hdrs, body + buf, b""
                buf += b
            body, buf = body + buf[:n], buf[n + 2:]
            if n == 0:
                return status, hdrs, body, buf
    if b"content-length" in hdrs:
        n = int(hdrs[b"content-length"])
        while len(buf) < n:
            b = s.recv(65536)
            if not b:
                break
            buf += b
        return status, hdrs, buf[:n], buf[n:]
    while True:
        b = s.recv(65536)
        if not b:
            return status, hdrs, buf, b""
        buf += b


def closed_after(s, limit):
    """whether the server closes s within limit seconds (what it sends then
    is ignored)"""
    s.settimeout(limit)
    try:
        while s.recv(65536):
            pass
        return True
    except OSError as e:
        return not isinstance(e, socket.timeout)


def upload(path, data, chunk=65536, pause=0, port=PORT, chunked=False, trailers=(),
           tpause=0, close=True):
    """send data to path, chunk bytes every pause seconds, then read the
    response; chunked with trailers sent tpause apart: status, headers, body"""
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
    try:
        conn = b"Connection: close\r\n" if close else b""
        if chunked:
            s.sendall(b"POST %s HTTP/1.1\r\nHost: x\r\n%sTransfer-Encoding: chunked\r\n\r\n"
                      % (path.encode(), conn))
        else:
            s.sendall(b"POST %s HTTP/1.1\r\nHost: x\r\n%sContent-Length: %d\r\n\r\n"
                      % (path.encode(), conn, len(data)))
        for i in range(0, len(data), chunk):
            part = data[i:i + chunk]
            s.sendall(b"%x\r\n%s\r\n" % (len(part), part) if chunked else part)
            if pause:
                time.sleep(pause)
        if chunked:
            s.sendall(b"0\r\n")
            for t in trailers:
                time.sleep(tpause)
                s.sendall(t + b"\r\n")
            time.sleep(tpause)
            s.sendall(b"\r\n")
        return recv_response(s)[:3]
    except OSError as e:
        return type(e).__name__, {}, b""
    finally:
        s.close()


def digest_of(data):
    return b"%d %s" % (len(data), hashlib.md5(data).hexdigest().encode())


def digest_ok(resp, data, how):
    """the answer's status and length/MD5 match: ok, the async waits (pull)
    or "async"/"sync" (sink)"""
    st, _, body = resp[:3]
    m = re.match(rb"(\d+ [0-9a-f]+) \(%s, (\w+)" % how.encode(), body or b"")
    if st != 200 or not m or m.group(1) != digest_of(data):
        return False, None
    w = m.group(2)
    return True, int(w) if w.isdigit() else w.decode()


def expect_100(path, data, wait=0.0):
    """Expect: 100-continue: the 100 must come before the body is sent (wait
    seconds after it): the response, whether the 100 came"""
    s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    try:
        s.sendall(b"POST %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                  b"Expect: 100-continue\r\nContent-Length: %d\r\n\r\n"
                  % (path.encode(), len(data)))
        st, _, rest = recv_head(s)
        if st != 100:
            return (st, {}, b""), False
        time.sleep(wait)
        s.sendall(data)
        return recv_response(s, rest)[:3], True
    except OSError as e:
        return (type(e).__name__, {}, b""), False
    finally:
        s.close()


def silent_mid_body(port, path="/pull"):
    """1000 of 10000 bytes, then nothing: the status (None if closed) and
    when"""
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
    t0 = time.monotonic()
    try:
        s.sendall(b"POST %s HTTP/1.1\r\nHost: x\r\nContent-Length: 10000\r\n\r\n"
                  % path.encode() + b"s" * 1000)
        st = recv_response(s)[0]
    except OSError:
        st = None
    finally:
        s.close()
    return st, round(time.monotonic() - t0, 1)


def raw_request(req, read_limit=10):
    """send req as is, the response's status and body"""
    s = socket.create_connection(("127.0.0.1", PORT), timeout=read_limit)
    try:
        s.sendall(req)
        return recv_response(s)[:3]
    except OSError as e:
        return type(e).__name__, {}, b""
    finally:
        s.close()


def tls_partial_record(size, cut, pause):
    """a TLS upload of size bytes to /pull whose last cut bytes (in a record)
    come pause seconds after the rest"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(inb, outb)
    s = socket.create_connection(("127.0.0.1", TLSPORT), timeout=30)
    try:
        while True:
            try:
                tls.do_handshake()
                break
            except ssl.SSLWantReadError:
                out = outb.read()
                if out:
                    s.sendall(out)
                b = s.recv(65536)
                if not b:
                    return None, b""
                inb.write(b)
        out = outb.read()
        if out:
            s.sendall(out)
        data = b"t" * size
        tls.write(b"POST /pull HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                  b"Content-Length: %d\r\n\r\n%s" % (size, data))
        raw = outb.read()
        s.sendall(raw[:-cut])
        time.sleep(pause)
        s.sendall(raw[-cut:])
        resp = b""
        while True:
            try:
                b = tls.read(65536)
                if not b:
                    break
                resp += b
                continue
            except ssl.SSLWantReadError:
                pass
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                break
            b = s.recv(65536)
            if not b:
                break
            inb.write(b)
        head, _, body = resp.partition(b"\r\n\r\n")
        st = int(head.split(b" ")[1]) if head else None
        return (st, {}, body), data
    finally:
        s.close()


def abort_mid_upload(i):
    s = socket.create_connection(("127.0.0.1", PORT), timeout=30)
    s.sendall(b"POST /pull HTTP/1.1\r\nHost: x\r\nContent-Length: 1048576\r\n\r\n"
              + b"a" * 100000)
    time.sleep(0.2)
    s.close()


def server_conns():
    """the established connections on the server's ports"""
    out = subprocess.run(["ss", "-Htn", "state", "established"], capture_output=True,
                         text=True).stdout
    return sum(1 for l in out.splitlines()
               if re.search(r"127\.0\.0\.1:(%d|%d|%d|%d)\s" % (PORT, RTPORT, TLSPORT, BPORT),
                            l))


def log():
    with open(os.path.join(work, "error_log")) as f:
        return f.read()


def log_count(what):
    return log().count(what)


def verdict(ok):
    return "OK" if ok else "FAIL"


def short(r):
    return repr(r)[:80]


report = []
responses = {}   # mode -> case -> outcome, compared between modes
for mode in os.environ.get("MODES", "sync async").split():
    is_async = mode == "async"
    resp = responses[mode] = {}
    p = start(MODES[mode])
    try:
        def case(name, outcome, ok, extra=""):
            resp[name] = outcome
            report.append("%s: %s: %s%s: %s" % (mode, name, short(outcome), extra,
                                                verdict(ok)))

        # Content-Length and chunked, small and 8MB, pull and sink
        small = bytes(range(256)) * 4
        big = bytes((i * 7) & 0xff for i in range(256)) * 32768
        for how in ("pull", "sink"):
            for size, data in (("1KB", small), ("8MB", big)):
                for chunked in (False, True):
                    r = upload("/%s" % how, data, chunked=chunked)
                    ok, w = digest_ok(r, data, how)
                    case("%s, %s %s" % (how, size, "chunked" if chunked else "C-L"),
                         (r[0], ok), ok, " (%s)" % (w,))

        # Crawling uploads (256KB, 16KB every 20ms), more than the threads:
        # no worker held while waiting
        data = bytes(range(256)) * 1024
        for how in ("pull", "sink"):
            wait_idle()
            n = 16 if is_async else THREADS
            smp = Sampler([0.15, 0.25])
            res, t = parallel(n, lambda i: upload("/%s?i=%d" % (how, i), data, 16384, 0.02))
            busy = smp.held()
            oks = [digest_ok(r, data, how) for r in res]
            ok = all(o[0] for o in oks)
            ws = sorted(set(str(o[1]) for o in oks if o[0]))
            if is_async:
                ok = ok and busy is not None and busy <= 1 and t < 2
            report.append("%s: %s, %d crawling 256KB uploads (16KB/20ms), %d threads: %ss, "
                          "workers held %s, waits %s, digests ok: %s"
                          % (mode, how, n, THREADS, t, busy, ws, verdict(ok)))

        # Chunked uploads whose trailers trickle (3 lines 300ms apart)
        data = b"c" * 4000
        wait_idle()
        n = 8 if is_async else THREADS
        smp = Sampler([0.6])
        res, t = parallel(n, lambda i: upload("/pull?t=%d" % i, data, 1000, 0, chunked=True,
                                              trailers=(b"X-A: 1", b"X-B: 2", b"X-C: 3"),
                                              tpause=0.3))
        busy = smp.held()
        ok = all(digest_ok(r, data, "pull")[0] for r in res)
        if is_async:
            ok = ok and t < 2 and busy is not None and busy <= 1
        report.append("%s: %d chunked uploads, trailers trickling (1.2s): %ss, workers held "
                      "%s, digests ok: %s" % (mode, n, t, busy, verdict(ok)))

        # Expect: 100-continue: the 100 comes before the body (sent 0.3s
        # later), without holding a worker meanwhile
        data = b"e" * 20000
        r, got100 = expect_100("/pull", data)
        ok = got100 and digest_ok(r, data, "pull")[0]
        case("Expect: 100-continue, pull", (r[0], got100, ok), ok)
        r, got100 = expect_100("/sink", data)
        ok = got100 and digest_ok(r, data, "sink")[0]
        case("Expect: 100-continue, sink", (r[0], got100, ok), ok)
        wait_idle()
        n = 16 if is_async else THREADS
        smp = Sampler([0.15, 0.25])
        res, t = parallel(n, lambda i: expect_100("/pull?e=%d" % i, data, 0.3))
        busy = smp.held()
        ok = all(r[1] and digest_ok(r[0], data, "pull")[0] for r in res)
        if is_async:
            ok = ok and busy is not None and busy <= 1 and t < 1.5
        report.append("%s: %d clients sending 0.3s after their 100 Continue: %ss, workers "
                      "held %s, all ok: %s" % (mode, n, t, busy, verdict(ok)))

        # LimitRequestBody: 413 by Content-Length, and mid-body (chunked)
        before = log()
        r = upload("/limited/x", b"l" * (2 * LIMIT))
        n588 = log().count("AH01588") - before.count("AH01588")
        case("LimitRequestBody, Content-Length over it", r[0], r[0] == 413 and n588 == 1,
             " (AH01588 logged %d)" % n588)
        before = log()
        r = upload("/limited/x", b"l" * (2 * LIMIT), chunk=16384, chunked=True)
        n591 = log().count("AH01591") - before.count("AH01591")
        case("LimitRequestBody, chunked over it mid-body", r[0], r[0] == 413 and n591 == 1,
             " (AH01591 logged %d)" % n591)

        # Read timeouts: Timeout 2 (the reader's 408 when async), then
        # RequestReadTimeout body=2 (Timeout 10: mod_reqtimeout's)
        before = log_count("timeout reading the request body (async)")
        st, t = silent_mid_body(PORT)
        n408 = log_count("timeout reading the request body (async)") - before
        ok = st in (408, None) and 1.5 <= t <= 3.5 and n408 == (1 if is_async else 0)
        case("client silent mid-body, Timeout 2", st, ok,
             " after %ss, the reader's 408 logged %d" % (t, n408))
        st, t = silent_mid_body(RTPORT)
        ok = st in (408, None) and 1.5 <= t <= 3.5
        case("client silent mid-body, RequestReadTimeout body=2 (Timeout 10)", st, ok,
             " after %ss" % t)
        st, t = silent_mid_body(PORT, "/sink")
        ok = st in (408, None) and 1.5 <= t <= 3.5
        case("client silent mid-body, sink, Timeout 2", st, ok, " after %ss" % t)

        # A malformed chunk: 400
        r = raw_request(b"POST /pull HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
                        b"3\r\nabc\r\nzz\r\n")
        case("malformed chunk", r[0], r[0] == 400)

        # TLS upload cut in its last record for 0.5s
        t0 = time.monotonic()
        r, data = tls_partial_record(32768, 100, 0.5)
        t = round(time.monotonic() - t0, 2)
        ok, w = digest_ok(r, data, "pull") if r else (False, None)
        case("TLS upload, a record cut for 0.5s", (r[0] if r else None, ok), ok and t < 2,
             " (%ss, %s waits)" % (t, w))

        # Clients aborting mid-upload: their connections go
        before = server_conns()
        parallel(4, abort_mid_upload)
        t0 = time.monotonic()
        while server_conns() > before and time.monotonic() - t0 < 5:
            time.sleep(0.05)
        left, t = server_conns() - before, round(time.monotonic() - t0, 2)
        report.append("%s: 4 clients aborting mid-upload: connections left %d after %ss: %s"
                      % (mode, left, t, verdict(left <= 0 and t < 2.5)))

        # The discard: a small leftover (the connection kept, the next request
        # served on it), over the limit by Content-Length (closed without
        # reading), chunked over the limit (closed once over it), a 100
        # Continue never sent (closed, nothing read)
        before = log()
        s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
        try:
            s.sendall(b"POST /discard HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n"
                      + b"d" * 500)
            time.sleep(0.3)
            s.sendall(b"d" * 500)
            st, _, body, rest = recv_response(s)
            s.sendall(b"GET /s/file.txt HTTP/1.1\r\nHost: x\r\n\r\n")
            st2, _, body2, _ = recv_response(s, rest)
        except OSError as e:
            st, body, st2, body2 = type(e).__name__, b"", None, b""
        finally:
            s.close()
        new = log()[len(before):]
        m = re.search(r"aptest-body: discard: (\w+) \((\d+) async waits\)", new)
        ok = (st == 200 and body == b"discard\n" and st2 == 200 and body2 == b"static file\n"
              and m is not None and m.group(1) == "OK"
              and (int(m.group(2)) >= 1) == is_async)
        case("discard, a small leftover: connection kept, next request served",
             (st, st2, m.group(1) if m else None), ok,
             " (%s async waits)" % (m.group(2) if m else None))

        def discard_close(head, send, name, outcome="DONE"):
            before = log()
            s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
            t0 = time.monotonic()
            try:
                s.sendall(head)
                stop_send = threading.Event()

                def sender():
                    try:
                        for part in send:
                            if stop_send.is_set():
                                break
                            s.sendall(part)
                    except OSError:
                        pass
                th = threading.Thread(target=sender)
                th.start()
                st, _, body, _ = recv_response(s)
                closed = closed_after(s, 3)
                stop_send.set()
                th.join()
            except OSError as e:
                st, body, closed = type(e).__name__, b"", None
            finally:
                s.close()
            t = round(time.monotonic() - t0, 2)
            new = log()[len(before):]
            m = re.search(r"aptest-body: discard: (\w+)", new)
            ok = (st == 200 and body == b"discard\n" and closed and t < 2
                  and m is not None and m.group(1) == outcome)
            case(name, (st, closed, m.group(1) if m else None), ok, " (%ss)" % t)

        discard_close(b"POST /discard HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n"
                      % (10 * LIMIT) + b"d" * 100, [],
                      "discard, Content-Length over the limit: closed without reading")
        discard_close(b"POST /discard HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n",
                      [b"4000\r\n" + b"d" * 0x4000 + b"\r\n"] * 40,
                      "discard, chunked over the limit: closed once over it")
        # (the response's head said the connection closes, ap_set_keepalive()
        # refusing a keep-alive while the client expects a 100: OK, closing)
        discard_close(b"POST /discard HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n"
                      b"Content-Length: 1000\r\n\r\n", [],
                      "discard, 100 Continue never sent: closed, nothing read", "OK")

        # A body read by AptestSuspend ("read") then replayed by an input
        # filter to mod_proxy_http (this server's /pull), mod_proxy_scgi and
        # mod_proxy_uwsgi: it arrives whole (r->read_length left alone)
        data = bytes((i * 13) & 0xff for i in range(100000))
        for chunked in (False, True):
            r = upload("/rp/x", data, chunk=16384, pause=0.01, chunked=chunked)
            ok = digest_ok(r, data, "pull")[0]
            read = r[1].get(b"ap-test-read1", b"").split()
            ok = ok and read[:1] == [b"%d" % len(data)]
            case("read, replayed to http (%s)" % ("chunked" if chunked else "C-L"),
                 (r[0], ok), ok, " (read: %s)" % read)
        for scheme, path in (("scgi", "/rs/x"), ("uwsgi", "/ru/x")):
            r = upload(path, data, chunk=16384, pause=0.01)
            got = r[1].get(b"x-body")
            ok = r[0] == 200 and got == b"%d" % len(data)
            case("read, replayed to %s" % scheme, (r[0], got), ok)

        # Blocking reads from an output filter while the request can suspend
        # (AP_REQUEST_BODY_BLOCK): no AGAIN, the body read whole
        data = b"b" * 100000
        for how in ("pull", "sink"):
            r = upload("/%sblock" % how, data, chunk=16384, pause=0.01)
            m = re.match(rb"(\d+ [0-9a-f]+) \(\w+ block, (\d+) AGAIN\)\nblock\n$", r[2] or b"")
            ok = (r[0] == 200 and m is not None and m.group(1) == digest_of(data)
                  and m.group(2) == b"0")
            case("%s from an output filter, blocking" % how, (r[0], ok), ok,
                 " (%s)" % short(r[2])[:60])

        text = log()
        findings = {
            "client waits (async)": text.count("waiting for the client (in) (async)")
                                    + text.count("waiting for the client (in/out) (async)"),
            "in/out waits (async)": text.count("waiting for the client (in/out) (async)"),
            "interrupted": text.count("reading the request body interrupted"),
            "abandoned": text.count("abandoned by its continuation"),
            "suspended blocking reads": text.count("a blocking read suspended"),
            "crashes": text.count("exit signal"),
            "errors": sum(1 for l in text.splitlines()
                          if (":error]" in l or ":crit]" in l or ":emerg]" in l)
                          and "MaxRequestWorkers" not in l),
        }
        report.append("%s: error_log: %s: %s"
                      % (mode, findings, verdict(findings["crashes"] == 0
                                                 and findings["errors"] == 0
                                                 and findings["abandoned"] == 0
                                                 and findings["suspended blocking reads"] == 0)))

        # Stops during uploads sending 1KB every 0.4s (4s): graceful (the
        # uploads may complete, GracefulShutdownTimeout 3), then immediate
        # (closed: the child exits without completing the waits): no hang,
        # no crash
        for how, sig in (("graceful", signal.SIGWINCH), ("immediate", signal.SIGTERM)):
            if how == "immediate":
                os.replace(os.path.join(work, "error_log"),
                           os.path.join(work, "error_log." + mode + "-1"))
                p = start(MODES[mode])
            n = 8 if is_async else THREADS
            res = [None] * n

            def one(i):
                res[i] = upload("/pull?g=%d" % i, b"g" * 10000, 1000, 0.4)[0]
            ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
            for th in ts:
                th.start()
            time.sleep(0.5)
            t0 = time.monotonic()
            p.send_signal(sig)
            try:
                p.wait(15)
                t = round(time.monotonic() - t0, 1)
            except subprocess.TimeoutExpired:
                kill_tree(p)
                t = None
            for th in ts:
                th.join()
            crashes = log_count("exit signal")
            wait_errors = log_count("reading the request body interrupted")
            ok = t is not None and t < 8 and not crashes
            if how == "immediate":
                ok = ok and 200 not in res and t < 3
            report.append("%s: %s stop during %d uploads: stopped after %ss, statuses %s, "
                          "wait errors logged %d, crashes %d: %s"
                          % (mode, how, n, t, sorted(set(map(str, res))), wait_errors,
                             crashes, verdict(ok)))
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
