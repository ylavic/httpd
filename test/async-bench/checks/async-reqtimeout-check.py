"""Check that mod_reqtimeout's RequestReadTimeout body= applies while mod_proxy_http
waits asynchronously for the client's body (the body read before the acquire, and
the send path), as when blocking ("sync"): a client stalling its body gets a 408 at
the body timeout (not the server's Timeout), logged by mod_reqtimeout (AH01382), and
a client keeping up with minrate is served past it.

usage: MODES="sync async" python3 -I async-reqtimeout-check.py HTTPD_PREFIX WORKDIR
"""

import hashlib
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

prefix, work = sys.argv[1], sys.argv[2]
os.makedirs(work, exist_ok=True)
BACKEND, FRONT, FRONT_MINRATE, FRONT_CAPPED = 18431, 18432, 18433, 18434
BODY_TIMEOUT = 3


class Backend(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        m = re.search(r"[?&]d=(\d+)", self.path)
        left = int(self.headers.get("Content-Length", "0"))
        h, n = hashlib.sha256(), 0
        while left > 0:
            b = self.rfile.read(min(left, 65536))
            if not b:
                break
            h.update(b)
            n += len(b)
            left -= len(b)
        if m:
            time.sleep(int(m.group(1)))  # answering late (?d=seconds)
        out = ("%d %s\n" % (n, h.hexdigest()[:16])).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *args):
        pass


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


backend = Server(("127.0.0.1", BACKEND), Backend)
threading.Thread(target=backend.serve_forever, daemon=True).start()

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{front}
Listen 127.0.0.1:{front_minrate}
Listen 127.0.0.1:{front_capped}
PidFile "{work}/httpd.pid"
ErrorLog "{work}/error_log"
LogLevel warn reqtimeout:info proxy_http:info
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule reqtimeout_module modules/mod_reqtimeout.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
ServerName localhost
StartServers 1
ServerLimit 1
ThreadsPerChild 4
MaxRequestWorkers 4
Timeout 30
RequestReadTimeout header=10 body={bt}
<Location "/up">
    ProxyPass "http://127.0.0.1:{backend}/up" max=32 timeout=30
    {asyncconf}
</Location>
<VirtualHost 127.0.0.1:{front_minrate}>
    RequestReadTimeout header=10 body={bt},minrate=1000
    <Location "/up">
        ProxyPass "http://127.0.0.1:{backend}/up" max=32 timeout=30
        {asyncconf}
    </Location>
</VirtualHost>
# mod_reqtimeout's deadline later than the server's Timeout (the time left
# capped at it)
<VirtualHost 127.0.0.1:{front_capped}>
    Timeout {bt}
    RequestReadTimeout header=10 body=10
    <Location "/up">
        ProxyPass "http://127.0.0.1:{backend}/up" max=32 timeout=30
        {asyncconf}
    </Location>
</VirtualHost>
"""

MODES = {"sync": "ProxyAsyncDelay -1", "async": "ProxyAsyncDelay 0\n    ProxyAsyncIdleTimeout 30"}


def start(conf):
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(CONF.format(prefix=prefix, work=work, front=FRONT, front_minrate=FRONT_MINRATE,
                            front_capped=FRONT_CAPPED, backend=BACKEND, bt=BODY_TIMEOUT,
                            asyncconf=conf))
    open(os.path.join(work, "error_log"), "w").close()
    p = subprocess.Popen([os.path.join(prefix, "bin", "httpd"), "-f",
                          os.path.join(work, "httpd.conf"), "-DFOREGROUND"])
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", FRONT), 0.2).close()
            return p
        except OSError:
            time.sleep(0.05)
    stop(p)
    raise SystemExit("httpd didn't start")


def stop(p):
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(15)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait(10)


def upload(total, first, chunk, gap, until=None, port=FRONT):
    """POST `total` bytes: `first` at once, then `chunk` every `gap` seconds
    (until `until` seconds, then stall). Returns (status, seconds)."""
    s = socket.create_connection(("127.0.0.1", port), 60)
    t0 = time.monotonic()
    s.sendall(b"POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % total)
    sent = first
    s.sendall(b"x" * first)
    s.setblocking(False)
    data = b""
    while True:
        try:
            b = s.recv(65536)
            if not b:
                break
            data += b
            if re.search(rb"\r\n\r\n", data):
                break
        except BlockingIOError:
            pass
        except OSError:
            break
        now = time.monotonic() - t0
        if sent < total and (until is None or now < until):
            n = min(chunk, total - sent)
            try:
                s.sendall(b"x" * n)
                sent += n
            except (BlockingIOError, OSError):
                pass
            time.sleep(gap)
        else:
            time.sleep(0.02)
        if now > 40:
            break
    s.close()
    m = re.match(rb"HTTP/1.1 (\d+)", data)
    return (int(m.group(1)) if m else None), time.monotonic() - t0


def logged_timeouts():
    with open(os.path.join(work, "error_log")) as f:
        return f.read().count("AH01382")


report = []


def check(mode, name, ok, detail):
    report.append(ok)
    print("%-5s %-52s %s  %s" % (mode, name, "OK  " if ok else "FAIL", detail))
    sys.stdout.flush()


for mode in os.environ.get("MODES", "sync async").split():
    p = start(MODES[mode])
    try:
        # Stalls within the first 16K (the body read before the acquire when
        # async), then past it (the send path)
        for name, first in (("stall in the first 16K", 1000), ("stall past 16K", 40000)):
            before = logged_timeouts()
            st, took = upload(100000, first, 0, 0.1, until=0)
            check(mode, "%s: 408 at body=%ds" % (name, BODY_TIMEOUT),
                  st == 408 and BODY_TIMEOUT - 0.5 < took < BODY_TIMEOUT + 2
                  and logged_timeouts() == before + 1,
                  "%s after %.1fs, AH01382 %d" % (st, took, logged_timeouts() - before))

        # minrate=1000: 2000 bytes/s for ~6s goes past the 3s, 200 bytes/s doesn't
        st, took = upload(12000, 1000, 400, 0.2, port=FRONT_MINRATE)
        check(mode, "minrate kept (2000 B/s for ~5.5s)", st == 200 and took > BODY_TIMEOUT,
              "%s after %.1fs" % (st, took))
        before = logged_timeouts()
        st, took = upload(12000, 1000, 40, 0.2, port=FRONT_MINRATE)
        check(mode, "minrate not kept (200 B/s): 408", st == 408 and took < 10
              and logged_timeouts() == before + 1, "%s after %.1fs" % (st, took))

        # body=10 but Timeout 3: the 408 at Timeout, both stalls
        for name, first in (("in the first 16K", 1000), ("past 16K", 40000)):
            st, took = upload(100000, first, 0, 0.1, until=0, port=FRONT_CAPPED)
            check(mode, "time left capped at Timeout=%ds, stall %s" % (BODY_TIMEOUT, name),
                  st == 408 and BODY_TIMEOUT - 0.5 < took < BODY_TIMEOUT + 2,
                  "%s after %.1fs" % (st, took))

        # A backend answering later than body=, the client pipelining its next
        # request past that deadline: the body was read in time (the body
        # stage ends at its EOS), so neither request is cut
        before = logged_timeouts()
        s = socket.create_connection(("127.0.0.1", FRONT), 10)
        s.sendall(b"POST /up?d=%d HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"
                  % (BODY_TIMEOUT + 2))
        time.sleep(BODY_TIMEOUT + 1)
        s.sendall(b"POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
        s.settimeout(15)
        data = b""
        while data.count(b"HTTP/1.1 200") < 2 or not data.endswith(b"\n"):
            try:
                b = s.recv(4096)
            except OSError:
                break
            if not b:
                break
            data += b
        s.close()
        check(mode, "backend slower than body=, client pipelining",
              data.count(b"HTTP/1.1 200") == 2 and logged_timeouts() == before,
              "%d responses, AH01382 %d"
              % (data.count(b"HTTP/1.1 200"), logged_timeouts() - before))
    finally:
        stop(p)

backend.shutdown()
sys.exit(0 if all(report) else 1)
