"""Check the core's request waits (ap_request_wait()) through mod_aptest's
"aptest-wait" handler, without mod_proxy: many timers on few threads,
crawling uploads and crawling readers, chunked uploads whose trailers
trickle, the read timeouts (Timeout, RequestReadTimeout), a TLS upload cut
in the middle of a record (the pending input that isn't readable), clients
aborting mid-upload, a notifier and its context serving several waits
(re-armed, a stale notification dropped, a re-arm in flight refused, a wait
without the re-arm declined and logged), descriptor contexts made in
subpools destroyed after their waits, and a graceful stop during waits. "sync" runs them with
AsyncRequests Off (every wait blocks: the same results, the threads held),
"async" with the waits in the MPM (no thread held while waiting); the
workers held (mod_status' BusyWorkers, but the status request's own) and
the times are checked in "async", and for the timers in "sync" too: as many
as the threads (all held, in one timer's time), as many more as wait for a
worker up to Timeout (one round of threads per timer), and beyond (all
served, none closed, the accepting stopped, the server serving after).

mod_aptest is built from ../../pyhttpd/mod_aptest with the install's apxs
into WORKDIR unless MOD_APTEST_SO is given.

usage: MODES="sync async" python3 -I async-wait-check.py HTTPD_PREFIX [MOD_APTEST_SO] WORKDIR
"""

import hashlib
import http.client
import math
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
PORT, RTPORT, TLSPORT = 18444, 18445, 18446
THREADS = 4
TIMEOUT = 2             # Timeout (s)
TIMER = 0.5             # /timer's wait (s)
PFDPOOL = 200           # /pfdpool's contexts
ADMISSION_BACKLOG = 16  # AsyncAdmissionBacklogPerThread

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

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{port}
Listen 127.0.0.1:{rtport}
Listen 127.0.0.1:{tlsport}
PidFile "{work}/httpd.pid"
ErrorLog "{work}/error_log"
LogLevel warn aptest:trace5 mpm_event:debug
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule status_module modules/mod_status.so
LoadModule reqtimeout_module modules/mod_reqtimeout.so
LoadModule ssl_module modules/mod_ssl.so
LoadModule aptest_module {aptest}
ServerName localhost
StartServers 1
ServerLimit 1
ThreadLimit {threads}
ThreadsPerChild {threads}
MaxRequestWorkers {threads}
MinSpareThreads 1
MaxSpareThreads {threads}
AsyncAdmissionBacklogPerThread {admission_backlog}
Timeout {timeout}
KeepAliveTimeout 5
GracefulShutdownTimeout 3
# Silent clients reach httpd at once (no TCP_DEFER_ACCEPT)
AcceptFilter http none
AcceptFilter https none
SendBufferSize 16384
RequestReadTimeout handshake=0 header=20 body=0
LogFormat "%r %>s %D" t
CustomLog "{work}/access_log" t
{modeconf}
<Location "/timer">
    SetHandler aptest-wait
    AptestWait timer {timer_ms}
</Location>
<Location "/longtimer">
    SetHandler aptest-wait
    AptestWait timer 5000
</Location>
<Location "/digest">
    SetHandler aptest-wait
    AptestWait digest
</Location>
<Location "/echo">
    SetHandler aptest-wait
    AptestWait echo
</Location>
<Location "/notifier">
    SetHandler aptest-wait
    AptestWait notifier
</Location>
<Location "/pfdpool">
    SetHandler aptest-wait
    AptestWait pfdpool {pfdpool}
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
                            tlsport=TLSPORT, aptest=aptest, threads=THREADS,
                            admission_backlog=ADMISSION_BACKLOG, timeout=TIMEOUT,
                            timer_ms=int(TIMER * 1000), pfdpool=PFDPOOL,
                            modeconf=modeconf))
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


def busy_workers(idle=False):
    st, body = get("/server-status?auto", timeout=5)
    m = re.search(rb"BusyWorkers: (\d+)", body) if st == 200 else None
    i = re.search(rb"IdleWorkers: (\d+)", body) if st == 200 else None
    if idle:
        return (int(m.group(1)) if m else None), (int(i.group(1)) if i else None)
    return int(m.group(1)) if m else None


def wait_idle(limit=5):
    """wait for every worker but the status request's to be idle: how long,
    None if not within limit seconds"""
    t0 = time.monotonic()
    while time.monotonic() - t0 < limit:
        if busy_workers(idle=True) == (1, THREADS - 1):
            return round(time.monotonic() - t0, 2)
        time.sleep(0.05)
    return None


class Sampler:
    """BusyWorkers every `interval` from `after` on, in the background (the
    status request itself is one of them), with when each was answered"""

    def __init__(self, after, n, interval):
        self.samples = []
        self.t0 = time.monotonic()
        self.t = threading.Thread(target=self.run, args=(after, n, interval))
        self.t.start()

    def run(self, after, n, interval):
        time.sleep(after)
        for _ in range(n):
            busy = busy_workers()
            self.samples.append((busy, time.monotonic() - self.t0))
            time.sleep(interval)

    def result(self):
        self.t.join()
        return self.samples


def held(samples, freed=None):
    """the worst number of workers held besides the status request's own,
    None if every status request timed out (all held); all of them (THREADS)
    for a status request answered only once the workers were freed, `freed`
    seconds after the sampler started (none was free to answer it before)"""
    vals = [THREADS if freed is not None and when >= freed else busy - 1
            for busy, when in samples if busy is not None]
    return max(vals) if vals else None


def parallel(n, fn):
    """fn(i) for i in range(n) at once (threads): the results, the time"""
    res = [None] * n

    def one(i):
        try:
            res[i] = fn(i)
        except Exception as e:  # report it, as a result
            res[i] = ("EXC", type(e).__name__)
    t0 = time.monotonic()
    ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return res, round(time.monotonic() - t0, 2)


def recv_response(s, slow=None):
    """read a whole response from s (slow: (bytes, pause) per read): status,
    headers (lowercase names), body (chunked decoded)"""
    data = b""
    while b"\r\n\r\n" not in data:
        b = s.recv(slow[0] if slow else 65536)
        if not b:
            return None, {}, b""
        data += b
    head, _, rest = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split(b" ")[1])
    hdrs = {}
    for l in lines[1:]:
        k, _, v = l.partition(b":")
        hdrs[k.strip().lower()] = v.strip()
    buf = rest
    while True:
        if b"content-length" in hdrs and len(buf) >= int(hdrs[b"content-length"]):
            return status, hdrs, buf[:int(hdrs[b"content-length"])]
        if hdrs.get(b"transfer-encoding") == b"chunked" and buf.endswith(b"0\r\n\r\n"):
            break
        if slow:
            time.sleep(slow[1])
        b = s.recv(slow[0] if slow else 65536)
        if not b:
            break
        buf += b
    if hdrs.get(b"transfer-encoding") != b"chunked":
        return status, hdrs, buf
    body = b""
    while buf:
        size, _, buf = buf.partition(b"\r\n")
        n = int(size.split(b";")[0], 16)
        if n == 0:
            break
        body += buf[:n]
        buf = buf[n + 2:]
    return status, hdrs, body


def digest_of(data):
    return b"%d %s" % (len(data), hashlib.md5(data).hexdigest().encode())


def digest_ok(resp, data):
    """the digest answer's status and length/MD5 match, its async waits"""
    st, _, body = resp
    m = re.match(rb"(\d+ [0-9a-f]+) \((\d+) async waits\)", body or b"")
    if st != 200 or not m or m.group(1) != digest_of(data):
        return False, None
    return True, int(m.group(2))


def upload(path, data, chunk, pause, port=PORT, chunked=False, trailers=(), tpause=0):
    """send data to path, chunk bytes every pause seconds, then read the
    response; chunked with trailers sent tpause apart"""
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
    try:
        if chunked:
            s.sendall(b"POST %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                      b"Transfer-Encoding: chunked\r\n\r\n" % path.encode())
        else:
            s.sendall(b"POST %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                      b"Content-Length: %d\r\n\r\n" % (path.encode(), len(data)))
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
        return recv_response(s)
    finally:
        s.close()


def echo_slow_reader(i, size, rchunk, rpause):
    """send size bytes to /echo at once (a thread) while reading the echo
    rchunk bytes every rpause through a small receive buffer"""
    data = bytes([65 + (i + k) % 26 for k in range(256)]) * (size // 256)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rchunk)
    s.settimeout(30)
    s.connect(("127.0.0.1", PORT))

    def send():
        try:
            s.sendall(b"POST /echo HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                      b"Content-Length: %d\r\n\r\n%s" % (len(data), data))
        except OSError:
            pass
    t = threading.Thread(target=send)
    t.start()
    try:
        st, _, body = recv_response(s, slow=(rchunk, rpause))
    finally:
        t.join()
        s.close()
    return st == 200 and body == data


def silent_mid_body(port):
    """1000 of 10000 bytes, then nothing: the status (None if closed) and
    when"""
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
    t0 = time.monotonic()
    try:
        s.sendall(b"POST /digest HTTP/1.1\r\nHost: x\r\nContent-Length: 10000\r\n\r\n"
                  + b"s" * 1000)
        st = recv_response(s)[0]
    except OSError:
        st = None
    finally:
        s.close()
    return st, round(time.monotonic() - t0, 1)


def tls_partial_record(size, cut, pause):
    """a TLS upload of size bytes to /digest whose last cut bytes (in a
    record) come pause seconds after the rest"""
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
        tls.write(b"POST /digest HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
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
    s.sendall(b"POST /digest HTTP/1.1\r\nHost: x\r\nContent-Length: 1048576\r\n\r\n"
              + b"a" * 100000)
    time.sleep(0.2)
    s.close()


def server_conns():
    """the established connections on the server's ports"""
    out = subprocess.run(["ss", "-Htn", "state", "established"], capture_output=True,
                         text=True).stdout
    return sum(1 for l in out.splitlines()
               if re.search(r"127\.0\.0\.1:(%d|%d|%d)\s" % (PORT, RTPORT, TLSPORT), l))


def timed_get(t0):
    """get() a timer: (status, body, when it ended since t0)"""
    def one(i):
        st, body = get("/timer?i=%d" % i, timeout=60)
        return st, body, time.monotonic() - t0
    return one


def timers_ok(res, waits):
    return all(r[0] == 200 and r[1].startswith(b"waited %d ms (%d async waits)"
                                               % (TIMER * 1000, waits)) for r in res)


def log_count(what):
    with open(os.path.join(work, "error_log")) as f:
        return f.read().count(what)


def log_findings():
    with open(os.path.join(work, "error_log")) as f:
        log = f.read()
    return {
        "timer waits (async)": log.count("] waiting for the timer (async)"),
        "client waits (async)": log.count("] waiting for the client (in) (async)"),
        "client output waits (async)": log.count("] waiting for the client (out) (async)"),
        "interrupted": log.count("interrupted (async"),
        "wait failures": log.count("aptest-wait: waiting for the"),
        "crashes": log.count("exit signal"),
        "errors": sum(1 for l in log.splitlines() if ":error]" in l or ":crit]" in l
                      or ":emerg]" in l),
    }


def verdict(ok):
    return "OK" if ok else "FAIL"


# Blocking ("sync"), a timer holds a worker: THREADS timers run at once, the
# others wait for a worker as new connections, a round of THREADS per timer.
# A new connection waits for a worker without a timeout (Timeout applies
# once a worker processes it), and mpm_event stops accepting (the others
# wait in the kernel's queue) once more than THREADS *
# AsyncAdmissionBacklogPerThread wait, or once they wait longer than
# AsyncAdmissionTarget for AsyncAdmissionInterval. The queued rounds wait
# up to Timeout.
QUEUE = min((math.ceil(TIMEOUT / TIMER) - 1) * THREADS, THREADS * ADMISSION_BACKLOG)
ROUNDS = 1 + math.ceil(QUEUE / THREADS)
# Twice as many: the last rounds wait longer than Timeout plus a timer, and
# THREADS more half a timer later, when the first ones have waited longer
# than AsyncAdmissionTarget (5ms) for AsyncAdmissionInterval (100ms): the
# accepting stops, every one served a round of THREADS per timer
OVERFLOW = 2 * (THREADS + QUEUE)
LATE = THREADS

report = []
for mode in os.environ.get("MODES", "sync async").split():
    is_async = mode == "async"
    p = start(MODES[mode])
    try:
        if is_async:
            # Timers all at once without holding a worker
            n = 200
            smp = Sampler(0.25, 1, 0)
            res, t = parallel(n, lambda i: get("/timer?i=%d" % i, timeout=60))
            busy = held(smp.result(), freed=0.9 * TIMER)
            ok = timers_ok(res, 1) and t < 3 * TIMER and busy is not None and busy <= 1
            report.append("%s: %d timers of %dms, %d threads: %ss, workers held %s, "
                          "all ok: %s%s"
                          % (mode, n, TIMER * 1000, THREADS, t, busy, verdict(ok),
                             "" if ok else " %s" % sorted(set(repr(r)[:60] for r in res))))
        else:
            # As many timers as threads: all at once, every worker held
            wait_idle()
            smp = Sampler(TIMER / 2, 1, 0)
            res, t = parallel(THREADS, lambda i: get("/timer?i=%d" % i, timeout=60))
            busy = held(smp.result(), freed=0.9 * TIMER)
            ok = timers_ok(res, 0) and TIMER <= t < 1.5 * TIMER and busy == THREADS
            report.append("%s: %d timers of %dms, %d threads: %ss, workers held %s, "
                          "all ok: %s%s"
                          % (mode, THREADS, TIMER * 1000, THREADS, t, busy, verdict(ok),
                             "" if ok else " %s" % sorted(set(repr(r)[:60] for r in res))))

            # As many more as wait for a worker without being closed: all
            # done, round after round of THREADS, a timer apart
            n = THREADS + QUEUE
            t0 = time.monotonic()
            res, t = parallel(n, timed_get(t0))
            ends = sorted(r[2] for r in res if len(r) == 3)
            rounds = [[round(e, 2) for e in ends[k * THREADS:(k + 1) * THREADS]]
                      for k in range(ROUNDS)]
            ok = (timers_ok(res, 0) and len(ends) == n
                  and all(abs(e - (k + 1) * TIMER) < 0.4 * TIMER
                          for k in range(ROUNDS) for e in rounds[k]))
            report.append("%s: %d timers of %dms (%d queued, Timeout %d), %d threads: %ss, "
                          "ends by round %s, none closed, all ok: %s%s"
                          % (mode, n, TIMER * 1000, QUEUE, TIMEOUT, THREADS, t,
                             [(r[0], r[-1]) for r in rounds if r], verdict(ok),
                             "" if ok else " %s" % sorted(set(repr(r)[:60] for r in res))))

            # Beyond: none closed while waiting for a worker, all served a
            # round of THREADS per timer, the accepting stopped, the server
            # serving after
            killed = log_count("killing unprocessed connection")
            suspended = log_count("Suspend listening sockets")
            n = OVERFLOW + LATE

            def overflow(i):
                if i >= OVERFLOW:
                    time.sleep(TIMER / 2)
                return get("/timer?i=%d" % i, timeout=60)
            res, t = parallel(n, overflow)
            served = sum(1 for r in res if r[0] == 200)
            closed = [r[0] for r in res if r[0] != 200]
            rounds_all = math.ceil(n / THREADS)
            ok = (timers_ok(res, 0) and served == n and not closed
                  and 0.9 * rounds_all * TIMER <= t < (rounds_all + 1) * TIMER)
            killed = log_count("killing unprocessed connection") - killed
            suspended = log_count("Suspend listening sockets") - suspended
            ok = ok and killed == 0 and suspended > 0 and not log_count("exit signal")
            idle = wait_idle()
            res2, t2 = parallel(THREADS, lambda i: get("/timer?i=%d" % i, timeout=60))
            ok2 = idle is not None and timers_ok(res2, 0) and t2 < 1.5 * TIMER
            report.append("%s: %d timers of %dms, %d threads: %ss, %d served, %d closed %s, "
                          "log: killed unprocessed %d, suspended accepting %d; idle after "
                          "%ss, then %d timers %ss: %s"
                          % (mode, n, TIMER * 1000, THREADS, t, served, len(closed),
                             sorted(set(map(str, closed))), killed, suspended, idle,
                             THREADS, t2, verdict(ok and ok2)))

        # Crawling uploads: 1MB, 16KB every 20ms
        data = bytes(range(256)) * 4096
        smp = Sampler(0.6, 1, 0)
        res, t = parallel(16, lambda i: upload("/digest?i=%d" % i, data, 16384, 0.02))
        busy = held(smp.result())
        oks = [digest_ok(r, data) for r in res]
        ok = all(o[0] for o in oks)
        waits = sorted(set(o[1] for o in oks if o[0]))
        if is_async:
            ok = ok and t < 3 and busy is not None and busy <= 1
        report.append("%s: 16 crawling 1MB uploads (16KB/20ms): %ss, workers held %s, "
                      "async waits %s, digests ok: %s"
                      % (mode, t, busy, (waits[0], waits[-1]) if waits else None, verdict(ok)))

        # Crawling readers of the echo: 1MB each, read 16KB every 20ms
        smp = Sampler(0.6, 1, 0)
        res, t = parallel(8, lambda i: echo_slow_reader(i, 1 << 20, 16384, 0.02))
        busy = held(smp.result())
        ok = all(r is True for r in res)
        if is_async:
            ok = ok and busy is not None and busy <= 1
        report.append("%s: 8 crawling readers of a 1MB echo (16KB/20ms): %ss, workers "
                      "held %s, echoes ok: %s" % (mode, t, busy, verdict(ok)))

        # Chunked uploads whose trailers trickle (3 lines 300ms apart)
        data = b"c" * 4000
        smp = Sampler(0.6, 1, 0)
        res, t = parallel(8, lambda i: upload("/digest?t=%d" % i, data, 1000, 0, chunked=True,
                                              trailers=(b"X-A: 1", b"X-B: 2", b"X-C: 3"),
                                              tpause=0.3))
        busy = held(smp.result())
        ok = all(digest_ok(r, data)[0] for r in res)
        if is_async:
            ok = ok and t < 2 and busy is not None and busy <= 1
        report.append("%s: 8 chunked uploads, trailers trickling (1.2s): %ss, workers held "
                      "%s, digests ok: %s" % (mode, t, busy, verdict(ok)))

        # Read timeouts: Timeout 2, then RequestReadTimeout body=2 (Timeout 10)
        st, t = silent_mid_body(PORT)
        ok = st in (408, None) and 1.5 <= t <= 3.5
        report.append("%s: client silent mid-body, Timeout 2: %s after %ss: %s"
                      % (mode, st, t, verdict(ok)))
        st, t = silent_mid_body(RTPORT)
        ok = st in (408, None) and 1.5 <= t <= 3.5
        report.append("%s: client silent mid-body, RequestReadTimeout body=2 (Timeout 10): "
                      "%s after %ss: %s" % (mode, st, t, verdict(ok)))

        # TLS upload cut in its last record for 0.5s
        t0 = time.monotonic()
        resp, data = tls_partial_record(32768, 100, 0.5)
        t = round(time.monotonic() - t0, 2)
        ok, waits = digest_ok(resp, data) if resp else (False, None)
        if is_async:
            ok = ok and waits is not None and waits <= 10
        report.append("%s: TLS upload, a record cut for 0.5s: %ss, async waits %s, "
                      "digest ok: %s" % (mode, t, waits, verdict(ok and t < 2)))

        # Clients aborting mid-upload: their connections go
        before = server_conns()
        parallel(4, abort_mid_upload)
        t0 = time.monotonic()
        while server_conns() > before and time.monotonic() - t0 < 5:
            time.sleep(0.05)
        left, t = server_conns() - before, round(time.monotonic() - t0, 2)
        report.append("%s: 4 clients aborting mid-upload: connections left %d after %ss: %s"
                      % (mode, left, t, verdict(left <= 0 and t < 2.5)))

        # A notifier and its context serving several waits (mod_aptest's
        # "notifier": re-arm refused in flight, the first wait notified from
        # another thread, a stale notification dropped by the re-arm, one made
        # after it counted, a wait without the re-arm declined and logged)
        unrearmed0 = log_count("served a wait already and wasn't re-armed")
        res, t = parallel(8, lambda i: get("/notifier?i=%d" % i, timeout=20))
        unrearmed = log_count("served a wait already and wasn't re-armed") - unrearmed0
        want = (b"notifier: busy=EBUSY wait1=ok stale=dropped prenotified=ok "
                b"unrearmed=declined\n" if is_async else b"notifier: declined\n")
        bodies = sorted(set(r[1] for r in res))
        ok = (all(r[0] == 200 and r[1] == want for r in res)
              and unrearmed == (8 if is_async else 0) and t < 2)
        report.append("%s: 8 notifier waits re-armed: %ss, bodies %s, unrearmed errors "
                      "logged %d: %s" % (mode, t, bodies, unrearmed, verdict(ok)))

        # Descriptor contexts in subpools: PFDPOOL each, two waits, destroyed
        # (every other one released first), on 4 requests at once
        smp = Sampler(0.1, 1, 0)
        res, t = parallel(4, lambda i: get("/pfdpool?i=%d" % i, timeout=30))
        busy = held(smp.result())
        want = b"pfdpool: %d contexts, %d async waits\n" % (PFDPOOL,
                                                           2 * PFDPOOL if is_async else 0)
        bodies = sorted(set(r[1] for r in res))
        bad = (log_count("can't release the descriptor")
               + log_count("wait context destroyed while it waits"))
        ok = all(r[0] == 200 and r[1] == want for r in res) and not bad
        report.append("%s: 4 x %d descriptor contexts in subpools: %ss, workers held %s, "
                      "bodies %s, release errors %d: %s"
                      % (mode, PFDPOOL, t, busy, bodies, bad, verdict(ok)))

        report.append("%s: error_log: %s" % (mode, log_findings()))

        # Graceful stop during 8 timers of 5s (GracefulShutdownTimeout 3): in
        # "sync", the THREADS of them waiting for a worker are served after
        # the first ones, a timer later
        res = [None] * 8

        def one(i):
            res[i] = get("/longtimer?i=%d" % i, timeout=20)[0]
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
        with open(os.path.join(work, "error_log")) as f:
            crashes = f.read().count("exit signal")
        if is_async:
            ok = t is not None and t < 8 and not crashes
        else:
            ok = (t is not None and t < 11 and not crashes
                  and all(s == 200 for s in res))
        report.append("%s: graceful stop during 8 timers of 5s: stopped after %ss, "
                      "statuses %s, crashes %d: %s"
                      % (mode, t, sorted(set(map(str, res))), crashes, verdict(ok)))
    finally:
        report.append("%s: %s" % (mode, stop(p)))
        os.replace(os.path.join(work, "error_log"), os.path.join(work, "error_log." + mode))
print("\n".join(report))
