"""Check paced output (ap_filter_pending_until()): mod_ratelimit pacing a
static file and a proxied stream without sleeping (many clients on few
threads, the rate kept), a FLUSH reaching it (mod_proxy_http streaming
blocking with ProxyAsyncDelay -1: it paces blocking, sleeping as before), mod_dialup's pulses a second apart on a
timer wait, pipelined paced responses in order, and no error line of the
core's held output invariants. "sync" runs them with AsyncRequests Off (the
filters sleep: the same bytes and rates, the threads held), "async" with the
waits in the MPM: the workers held (mod_status' BusyWorkers, but the status
request's own) and the times are checked there.

The Go backend (../backend) must be built.

usage: MODES="sync async" python3 -I async-pace-check.py HTTPD_PREFIX WORKDIR
"""

import http.client
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time

here = os.path.dirname(os.path.abspath(__file__))
prefix, work = sys.argv[1], sys.argv[2]
os.makedirs(work, exist_ok=True)
PORT, BACKEND = 18463, 18464
THREADS = 4
RATE = 200                 # mod_ratelimit's rate-limit (KB/s)
SIZE = 200 * 1024          # 5 chunks of 200ms: 4 intervals
PACED = 1.0                # how long a paced response lasts (s): 5 intervals
MODEM_SIZE = 21000         # V.92 (7000 B/s): 3 pulses, 2 waits of 1s
PULSED = 2.0

docs = os.path.join(work, "docs")
FILES = {
    "file.bin": bytes([(i * 13) % 251 for i in range(SIZE)]),
    "modem.bin": bytes([65 + i % 26 for i in range(MODEM_SIZE)]),
}
for d in ("", "rl", "modem"):
    os.makedirs(os.path.join(docs, d), exist_ok=True)
    for name, data in FILES.items():
        with open(os.path.join(docs, d, name), "wb") as f:
            f.write(data)

backend = subprocess.Popen([os.path.join(here, "..", "backend"),
                            "-addr", "127.0.0.1:%d" % BACKEND])
STREAM = "s=%d&c=16384&i=20000" % SIZE  # chunks 20ms apart: reads that would block

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{port}
PidFile "{work}/httpd.pid"
ErrorLog "{work}/error_log"
LogLevel warn
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule status_module modules/mod_status.so
LoadModule env_module modules/mod_env.so
LoadModule ratelimit_module modules/mod_ratelimit.so
LoadModule dialup_module modules/mod_dialup.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
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
Timeout 10
KeepAliveTimeout 5
AcceptFilter http none
EnableSendfile off
EnableMMAP off
LogFormat "%r %>s %D" t
CustomLog "{work}/access_log" t
ProxyAsyncDelay 0
{modeconf}
<Location "/rl/">
    SetOutputFilter RATE_LIMIT
    SetEnv rate-limit {rate}
</Location>
<Location "/rlproxy/">
    SetOutputFilter RATE_LIMIT
    SetEnv rate-limit {rate}
    ProxyPass "http://127.0.0.1:{backend}/"
</Location>
<Location "/rlflush/">
    SetOutputFilter RATE_LIMIT
    SetEnv rate-limit {rate}
    ProxyPass "http://localhost:{backend}/"
    ProxyAsyncDelay -1
</Location>
<Location "/modem/">
    ModemStandard V.92
</Location>
<Location "/server-status">
    SetHandler server-status
</Location>
"""
MODES = {"sync": "AsyncRequests Off", "async": ""}


def start(modeconf):
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(CONF.format(prefix=prefix, work=work, port=PORT, backend=BACKEND, docs=docs,
                            threads=THREADS, rate=RATE, modeconf=modeconf))
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


def stop(p):
    if p.poll() is not None:
        return "stopped already"
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


def get(path, timeout=30):
    """status, body, seconds"""
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    t0 = time.monotonic()
    try:
        c.request("GET", path)
        r = c.getresponse()
        body = r.read()
        return r.status, body, round(time.monotonic() - t0, 2)
    except (http.client.HTTPException, OSError) as e:
        return type(e).__name__, b"", round(time.monotonic() - t0, 2)
    finally:
        c.close()


def busy_workers():
    st, body, _ = get("/server-status?auto", timeout=5)
    m = re.search(rb"BusyWorkers: (\d+)", body) if st == 200 else None
    return int(m.group(1)) if m else None


class Sampler:
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
        self.t.join()
        return max(THREADS if b is None else b - 1 for b in self.samples)


def parallel(n, fn):
    res = [None] * n

    def one(i):
        res[i] = fn(i)
    t0 = time.monotonic()
    ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return res, round(time.monotonic() - t0, 2)


def median(v):
    v = sorted(v)
    return v[len(v) // 2]


def verdict(ok):
    return "OK" if ok else "FAIL"


INVARIANTS = ("hold output at the request's end", "hold output at an internal redirect",
              "holds again after its hold's wait failed", "exit signal")

report = []
for mode in os.environ.get("MODES", "sync async").split():
    p = start(MODES[mode])
    asyn = (mode == "async")
    try:
        # mod_ratelimit: a static file and a proxied stream, 8 clients on 4
        # threads, each paced at the rate
        for what, path, size in (("a static file", "/rl/file.bin", SIZE),
                                 ("a proxied stream", "/rlproxy/?" + STREAM, SIZE)):
            n = 8
            sampler = Sampler(PACED / 2, 3, 0.1)
            res, t = parallel(n, lambda i: get("%s%si=%d" % (path, "&" if "?" in path else "?", i)))
            busy = sampler.held()
            good = all(r[0] == 200 and len(r[1]) == size
                       and (what != "a static file" or r[1] == FILES["file.bin"]) for r in res)
            each = median([r[2] for r in res])
            if asyn:
                ok = good and busy <= 1 and t < PACED * 1.6 and PACED * 0.7 <= each <= PACED * 1.4
            else:
                ok = good and t >= PACED * n / THREADS * 0.85
            report.append("%s: rate-limit %dKB/s, %d clients, %s of %dKB: %.2fs, each %.2fs "
                          "(paced: %.2fs), workers held %s, bodies %s: %s"
                          % (mode, RATE, n, what, size // 1024, t, each, PACED, busy,
                             "ok" if good else "WRONG", verdict(ok)))

        # A FLUSH reaching mod_ratelimit (mod_proxy_http streaming blocking,
        # ProxyAsyncDelay -1, flushes when the backend has nothing yet):
        # paced blocking (sleeping), the rate kept
        n = 2
        sampler = Sampler(PACED / 2, 3, 0.1)
        res, t = parallel(n, lambda i: get("/rlflush/?%s&f=%d" % (STREAM, i)))
        busy = sampler.held()
        good = all(r[0] == 200 and len(r[1]) == SIZE for r in res)
        each = median([r[2] for r in res])
        ok = good and busy >= 1 and PACED * 0.7 <= each <= PACED * 1.6
        report.append("%s: rate-limit, a blocking proxied stream (FLUSH): %d clients %.2fs, each %.2fs, "
                      "workers held %s (sleeping), bodies %s: %s"
                      % (mode, n, t, each, busy, "ok" if good else "WRONG", verdict(ok)))

        # mod_dialup's pulses a second apart
        n = 8
        sampler = Sampler(PULSED / 2, 3, 0.2)
        res, t = parallel(n, lambda i: get("/modem/modem.bin?i=%d" % i))
        busy = sampler.held()
        good = all(r[0] == 200 and r[1] == FILES["modem.bin"] for r in res)
        each = median([r[2] for r in res])
        if asyn:
            ok = good and busy <= 1 and t < PULSED * 1.5 and PULSED * 0.8 <= each <= PULSED * 1.3
        else:
            ok = good and t >= PULSED * n / THREADS * 0.85
        report.append("%s: mod_dialup V.92, %d clients, %d bytes: %.2fs, each %.2fs (pulses: "
                      "%.1fs), workers held %s, bodies %s: %s"
                      % (mode, n, MODEM_SIZE, t, each, PULSED, busy,
                         "same" if good else "DIFFER", verdict(ok)))

        # Two paced responses pipelined before a plain one: in order
        s = socket.create_connection(("127.0.0.1", PORT), timeout=30)
        t0 = time.monotonic()
        try:
            s.sendall(b"GET /rl/file.bin?p=1 HTTP/1.1\r\nHost: x\r\n\r\n"
                      b"GET /rl/file.bin?p=2 HTTP/1.1\r\nHost: x\r\n\r\n"
                      b"GET /modem.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            data = b""
            while True:
                b = s.recv(65536)
                if not b:
                    break
                data += b
        finally:
            s.close()
        t = round(time.monotonic() - t0, 2)
        parts = data.split(b"HTTP/1.1 200 OK")
        ok = (len(parts) == 4 and FILES["file.bin"] in parts[1] and FILES["file.bin"] in parts[2]
              and parts[3].endswith(FILES["modem.bin"]) and t >= PACED * 2 * 0.8)
        report.append("%s: 2 paced responses pipelined before a plain one: %d responses in "
                      "%.2fs, in order %s: %s" % (mode, len(parts) - 1, t, ok, verdict(ok)))

        with open(os.path.join(work, "error_log")) as f:
            log = f.read()
        bad = {k: log.count(k) for k in INVARIANTS if k in log}
        report.append("%s: error_log: invariants/crashes %s: %s"
                      % (mode, bad or "none", verdict(not bad)))
    finally:
        report.append("%s: %s" % (mode, stop(p)))
        os.replace(os.path.join(work, "error_log"), os.path.join(work, "error_log." + mode))
backend.terminate()
backend.wait(5)
print("\n".join(report))
