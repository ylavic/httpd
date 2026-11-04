"""Check mod_proxy_fcgi waiting for the backend without holding a worker
thread (ap_proxy_wait()), against fcgibackend. Also its flushes
(flushpackets=on) and an error's large ErrorDocument after an async wait,
to a client that stops reading: no worker held.

usage: MODES="sync async" python3 -I async-fcgi-check.py HTTPD_PREFIX WORKDIR
"""

import http.client
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

prefix, work = sys.argv[1], sys.argv[2]
os.makedirs(os.path.join(work, "htdocs"), exist_ok=True)
with open(os.path.join(work, "htdocs", "big.html"), "wb") as f:
    f.write(b"e" * (2 << 20))
FRONT, FCGI, RAW, DOWN = 18432, 18433, 18434, 18435
here = os.path.dirname(os.path.abspath(__file__))
backend = subprocess.Popen([os.path.join(here, "..", "fcgibackend"),
                            "-addr", "127.0.0.1:%d" % FCGI,
                            "-raw", "127.0.0.1:%d" % RAW])

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
LoadModule proxy_fcgi_module modules/mod_proxy_fcgi.so
ServerName localhost
DocumentRoot "{work}/htdocs"
# Not to absorb a stalled client's response (autotuning)
SendBufferSize 65536
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
# Distinct worker URLs, not shared (timeout= and disablereuse= apply)
ProxyPass "/fcgi/" "fcgi://127.0.0.1:{fcgi}/fcgi/"
ProxyPass "/to/" "fcgi://127.0.0.1:{fcgi}/to/" timeout=1
ProxyPass "/ka/" "fcgi://127.0.0.1:{fcgi}/ka/" disablereuse=off
ProxyPass "/raw/" "fcgi://127.0.0.1:{raw}/"
ProxyPass "/down/" "fcgi://127.0.0.1:{down}/"
ProxyPass "/fl/" "fcgi://127.0.0.1:{fcgi}/fl/" flushpackets=on
ProxyPass "/eto/" "fcgi://127.0.0.1:{fcgi}/eto/" timeout=1
<Location "/eto/">
    ErrorDocument 504 /big.html
</Location>
"""


def start(async_conf):
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(CONF.format(prefix=prefix, work=work, front=FRONT, fcgi=FCGI, raw=RAW,
                            down=DOWN, asyncconf=async_conf))
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


def request(method, path, body=None, conn=None, timeout=20):
    c = conn or http.client.HTTPConnection("127.0.0.1", FRONT, timeout=timeout)
    try:
        c.request(method, path, body=body)
        r = c.getresponse()
        data = r.read()
        return r.status, data
    except (http.client.HTTPException, OSError) as e:
        return type(e).__name__, b""
    finally:
        if not conn:
            c.close()


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
    return time.monotonic() - t0, ok, [r[0] for r in res] if not ok else ""


def timed(fn, *args):
    t0 = time.monotonic()
    r = fn(*args)
    return r, round(time.monotonic() - t0, 2)


def pipelined(n, delay_ms):
    s = socket.create_connection(("127.0.0.1", FRONT), timeout=20)
    reqs = b"".join(b"GET /fcgi/p?d=%d&n=%d HTTP/1.1\r\nHost: x\r\n%s\r\n"
                    % (delay_ms, i, b"Connection: close\r\n" if i == n - 1 else b"")
                    for i in range(n))
    s.sendall(reqs)
    data = b""
    while True:
        b = s.recv(65536)
        if not b:
            break
        data += b
    s.close()
    return data.count(b"HTTP/1.1 200 OK"), data.count(b"x" * 512)


def backend_conns():
    """the established connections to the backend's port (ss, else netstat,
    e.g. on FreeBSD)"""
    if shutil.which("ss"):
        out = subprocess.run(["ss", "-Htn", "state", "established", "dst",
                              "127.0.0.1:%d" % FCGI], capture_output=True, text=True).stdout
        return len(out.splitlines())
    out = subprocess.run(["netstat", "-n", "-p", "tcp"], capture_output=True, text=True).stdout
    return sum(1 for line in out.splitlines()
               if "ESTABLISHED" in line and line.split()[4] == "127.0.0.1.%d" % FCGI)


def keepalive(n):
    c = http.client.HTTPConnection("127.0.0.1", FRONT, timeout=20)
    sts = [request("GET", "/ka/k?d=100", conn=c)[0] for _ in range(n)]
    conns = backend_conns()
    c.close()
    return sts, conns


def stalling(path, stall, res, i, first=65536):
    """GET path, read `first` bytes, then nothing for `stall` seconds (a
    small receive buffer), then the rest: (status line, bytes, seconds)."""
    t0 = time.monotonic()
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    s.settimeout(30)
    got, head = 0, b""
    try:
        s.connect(("127.0.0.1", FRONT))
        s.sendall(b"GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
                  % path.encode())
        while got < first:
            b = s.recv(16384)
            if not b:
                break
            got += len(b)
            if len(head) < 64:
                head += b
        time.sleep(stall)
        while True:
            b = s.recv(65536)
            if not b:
                break
            got += len(b)
    except OSError as e:
        head = type(e).__name__.encode()
    finally:
        s.close()
    res[i] = (head.split(b"\r\n", 1)[0].decode(), got, round(time.monotonic() - t0, 2))


def stalled_and_fast(path, n, stall):
    """n clients stalling (stalling()) on path, and 4 fast requests 1s
    later, while they stall: the fast requests' longest time and statuses,
    and the stalled clients' results."""
    res, fast = [None] * n, [None] * 4
    ts = [threading.Thread(target=stalling, args=(path, stall, res, i)) for i in range(n)]
    for t in ts:
        t.start()
    time.sleep(1)

    def one(i):
        t0 = time.monotonic()
        r = request("GET", "/fcgi/f?d=0&i=%d" % i, timeout=30)
        fast[i] = (r[0], time.monotonic() - t0)
    tf = [threading.Thread(target=one, args=(i,)) for i in range(4)]
    for t in tf:
        t.start()
    for t in tf + ts:
        t.join()
    return (round(max(t for st, t in fast), 2), sorted(set(st for st, t in fast)), res)


def log_findings():
    with open(os.path.join(work, "error_log")) as f:
        log = f.read()
    return {
        # mod_proxy's own lines, or the core's (ap_request_wait()) for the
        # backend's socket
        "waiting (async)": (log.count("proxy: waiting for the backend (async)")
                            + log.count("] waiting for the descriptor (in) (async)")),
        "done waiting (async)": (log.count("done waiting for the backend (async)")
                                 + log.count("done waiting for the descriptor (in) (async)")),
        "can't wait": (log.count("can't wait for the backend asynchronously")
                       + log.count("can't wait for the descriptor asynchronously")),
        "crashes": log.count("exit signal"),
        "errors": sum(1 for l in log.splitlines() if ":error]" in l or ":crit]" in l
                      or ":emerg]" in l),
    }


report = []
MODES = {"sync": "ProxyAsyncDelay -1", "async": "ProxyAsyncDelay 0"}
ok512 = lambda r: r[0] == 200 and r[1] == b"x" * 512
big = 4 << 20
for mode in os.environ.get("MODES", "sync async").split():
    p = start(MODES[mode])
    try:
        report.append("%s: 10 concurrent 1s responses, 2 workers: %.2fs, all ok: %s %s"
                      % ((mode,) + concurrent(10, "/fcgi/slow?d=1000", ok512)))
        r, t = timed(request, "GET", "/to/t?d=3000")
        report.append("%s: timeout=1 vs a 3s backend: %s in %ss" % (mode, r[0], t))
        r, t = timed(request, "GET", "/fcgi/big?s=%d&c=65536&i=2000" % big)
        report.append("%s: 4MB streamed by 64KB every 2ms: %s, %d bytes, %ss"
                      % (mode, r[0], len(r[1]), t))
        report.append("%s: 4 concurrent 4MB, 2 workers: %.2fs, all ok: %s %s"
                      % ((mode,) + concurrent(4, "/fcgi/big?s=%d&c=65536&i=2000" % big,
                                              lambda r: r[0] == 200 and len(r[1]) == big)))
        r, t = timed(request, "POST", "/fcgi/post?d=500", b"y" * (1 << 20))
        report.append("%s: 1MB POST, 0.5s backend: %s, ok: %s, %ss" % (mode, r[0], ok512(r), t))
        r, t = timed(request, "GET", "/raw/r?d=500&close=0")
        report.append("%s: backend closing without answering (0.5s): %s in %ss" % (mode, r[0], t))
        r, t = timed(request, "GET", "/raw/r?d=500&close=1")
        report.append("%s: backend closing mid-body (0.5s): %s %r in %ss" % (mode, r[0], r[1], t))
        r, t = timed(request, "GET", "/down/d")
        report.append("%s: backend down: %s in %ss" % (mode, r[0], t))
        report.append("%s: 3 pipelined 0.3s requests (200s, bodies): %s" % (mode, pipelined(3, 300)))
        report.append("%s: 5 requests with backend keep-alive (statuses, backend conns): %s"
                      % (mode, keepalive(5)))
        report.append("%s: 2 clients stalling 3s in a 2MB response flushed every 32KB "
                      "(flushpackets=on), 2 workers, 4 fast requests meanwhile (max time, "
                      "statuses), the stalled ones: %s"
                      % (mode, stalled_and_fast("/fl/s?s=%d&c=32768&i=10000" % (2 << 20), 2, 3)))
        report.append("%s: 2 clients stalling 3s in a 2MB ErrorDocument of a timeout=1 "
                      "after an async wait, 4 fast requests meanwhile (max time, statuses), "
                      "the stalled ones: %s"
                      % (mode, stalled_and_fast("/eto/e?d=1500", 2, 3)))
        report.append("%s: after all, 10 concurrent 1s again: %.2fs, all ok: %s %s"
                      % ((mode,) + concurrent(10, "/fcgi/slow?d=1000", ok512)))
        report.append("%s: error_log: %s" % (mode, log_findings()))
    finally:
        report.append("%s: %s" % (mode, stop(p)))
        os.replace(os.path.join(work, "error_log"), os.path.join(work, "error_log." + mode))
backend.terminate()
print("\n".join(report))
