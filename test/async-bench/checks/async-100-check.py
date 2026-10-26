"""Check Expect: 100-continue through mod_proxy_http, blocking ("sync") and
async (ProxyAsyncDelay 0): end-to-end (the client expects the 100) and the
worker's ping= (the proxy asks for it), with the backend answering the 100
late, never (ping timeout: 503), or with a final response instead; and that
async requests waiting for the 100 or the final response don't hold a worker.

usage: MODES="sync async" python3 -I async-100-check.py HTTPD_PREFIX WORKDIR
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
from urllib.parse import parse_qs, urlparse

prefix, work = sys.argv[1], sys.argv[2]
os.makedirs(work, exist_ok=True)
BACKEND, FRONT, BACKEND_SLOWHEAD = 18431, 18432, 18433
seen_expect = {}  # id -> whether the backend got "Expect: 100-continue"
final_body = {}  # id -> the body length read after a "final-ka" response


def backend_conn(s):
    f = s.makefile("rb")
    try:
        while True:
            line = f.readline()
            if not line:
                return
            _, path, _ = line.decode().split()
            headers = {}
            while True:
                h = f.readline()
                if h in (b"\r\n", b""):
                    break
                k, v = h.decode().split(":", 1)
                headers[k.strip().lower()] = v.strip()
            q = parse_qs(urlparse(path).query)
            mode = q.get("m", ["continue"])[0]
            d1, d2 = float(q.get("d1", ["1"])[0]), float(q.get("d2", ["1"])[0])
            expect = headers.get("expect", "").lower() == "100-continue"
            seen_expect[q.get("id", ["?"])[0]] = expect
            n = int(headers.get("content-length", "0"))
            if mode == "stall":
                time.sleep(10)
                return
            if mode == "final":
                s.sendall(b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n"
                          b"Connection: close\r\n\r\n")
                return
            if mode == "final-ka":
                # A final response, keeping the connection: the body follows
                s.sendall(b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n")
                final_body[q.get("id", ["?"])[0]] = len(f.read(n)) if n else 0
                continue
            if expect:
                time.sleep(d1)
                s.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
            body = f.read(n) if n else b""
            time.sleep(d2)
            out = ("%d %s\n" % (len(body), hashlib.sha256(body).hexdigest()[:16])).encode()
            s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(out), out))
    except OSError:
        pass
    finally:
        s.close()


def slowhead_conn(s):
    """A backend taking its time to read the request's head (small receive
    buffer, nothing read for 3s, longer than httpd takes with a huge head), then
    as backend_conn() for 100-continue."""
    time.sleep(3)
    backend_conn(s)


def listen(port, rcvbuf=None):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if rcvbuf:
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    ls.bind(("127.0.0.1", port))
    ls.listen(128)
    return ls


def serve(ls, handler):
    while True:
        try:
            s, _ = ls.accept()
        except OSError:
            return
        threading.Thread(target=handler, args=(s,), daemon=True).start()


threading.Thread(target=serve, args=(listen(BACKEND), backend_conn),
                 daemon=True).start()
threading.Thread(target=serve, args=(listen(BACKEND_SLOWHEAD, 4096), slowhead_conn),
                 daemon=True).start()

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{front}
PidFile "{work}/httpd.pid"
ErrorLog "{work}/error_log"
LogLevel warn proxy_http:trace5
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule env_module modules/mod_env.so
ServerName localhost
StartServers 1
ServerLimit 1
ThreadLimit 2
ThreadsPerChild 2
MaxRequestWorkers 2
MinSpareThreads 1
MaxSpareThreads 2
Timeout 10
LimitRequestFields 1000
# Not to have the core write the huge heads blocking above 64KB (flow control)
FlushMaxThreshold 16777216
LogFormat "%U%q %>s %D" t
CustomLog "{work}/access_log" t
<Location "/e2e">
    ProxyPass "http://127.0.0.1:{backend}/e2e" max=32 timeout=10
    {asyncconf}
</Location>
<Location "/ping">
    ProxyPass "http://127.0.0.1:{backend}/ping" max=32 timeout=10 ping=2
    {asyncconf}
</Location>
<Location "/off">
    Proxy100Continue Off
    ProxyPass "http://127.0.0.1:{backend}/off" max=32 timeout=10
    {asyncconf}
</Location>
<Location "/slowhead">
    ProxyPass "http://127.0.0.1:{slowhead}/slowhead" max=32 timeout=10
    {asyncconf}
</Location>
<Location "/suppress">
    SetEnv proxy-interim-response Suppress
    ProxyPass "http://127.0.0.1:{backend}/suppress" max=32 timeout=10
    {asyncconf}
</Location>
"""

MODES = {"sync": "ProxyAsyncDelay -1", "async": "ProxyAsyncDelay 0\n    ProxyAsyncIdleTimeout 10"}


def start(conf):
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(CONF.format(prefix=prefix, work=work, front=FRONT, backend=BACKEND,
                            slowhead=BACKEND_SLOWHEAD,
                            asyncconf=conf))
    for name in ("error_log", "access_log"):
        open(os.path.join(work, name), "w").close()
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


def read_response(s):
    """The final response (status, body), skipping interim ones, and
    whether a 100 Continue came first."""
    data, got_100 = b"", False
    while True:
        while b"\r\n\r\n" not in data:
            b = s.recv(65536)
            if not b:
                return None, data, got_100
            data += b
        head, data = data.split(b"\r\n\r\n", 1)
        status = int(head.split()[1])
        if status == 100:
            got_100 = True
            continue
        m = re.search(rb"(?i)content-length: *(\d+)", head)
        n = int(m.group(1)) if m else 0
        while len(data) < n:
            b = s.recv(65536)
            if not b:
                break
            data += b
        return status, data[:n], got_100


def post(path, body, expect, extra=b""):
    """POST like curl: with Expect, the body is sent once the 100 comes (or
    the final response), extra being more header lines. Returns (status,
    body, got_100)."""
    s = socket.create_connection(("127.0.0.1", FRONT), 20)
    head = (b"POST %s HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n%s%s\r\n"
            % (path.encode(), len(body), b"Expect: 100-continue\r\n" if expect else b"",
               extra))
    s.sendall(head)
    if expect:
        data = b""
        while b"\r\n\r\n" not in data:
            b = s.recv(65536)
            if not b:
                break
            data += b
        if data.startswith(b"HTTP/1.1 100"):
            s.sendall(body)
            rest = data.split(b"\r\n\r\n", 1)[1]
            status, rbody, _ = read_response_from(s, rest)
            s.close()
            return status, rbody, True
        status, rbody, _ = read_response_from(s, data)
        s.close()
        return status, rbody, False
    s.sendall(body)
    r = read_response(s)
    s.close()
    return r


def read_response_from(s, already):
    class Buf:
        def __init__(self, sock, data):
            self.sock, self.data = sock, data

        def recv(self, n):
            if self.data:
                d, self.data = self.data, b""
                return d
            return self.sock.recv(n)
    return read_response(Buf(s, already))


def digest(body):
    return ("%d %s\n" % (len(body), hashlib.sha256(body).hexdigest()[:16])).encode()


report = []


def check(mode, name, ok, detail):
    report.append(ok)
    print("%-5s %-50s %s  %s" % (mode, name, "OK  " if ok else "FAIL", detail))
    sys.stdout.flush()


def errlog(text):
    with open(os.path.join(work, "error_log")) as f:
        return f.read().count(text)


body = os.urandom(100000)
for mode in os.environ.get("MODES", "sync async").split():
    p = start(MODES[mode])
    try:
        t0 = time.monotonic()
        st, rb, got = post("/e2e?d1=0.5&d2=0.5&id=%s-e2e" % mode, body, True)
        check(mode, "end-to-end: 100 forwarded, body, 200",
              st == 200 and got and rb == digest(body) and seen_expect.get(mode + "-e2e"),
              "%s, 100 %s, %.2fs" % (st, got, time.monotonic() - t0))

        t0 = time.monotonic()
        st, rb, got = post("/ping?d1=0.5&d2=0.5&id=%s-ping" % mode, body, False)
        check(mode, "ping: proxy asks for 100, body, 200",
              st == 200 and rb == digest(body) and seen_expect.get(mode + "-ping"),
              "%s, backend got Expect %s, %.2fs" % (st, seen_expect.get(mode + "-ping"),
                                                     time.monotonic() - t0))

        t0 = time.monotonic()
        st, rb, got = post("/ping?m=stall&id=%s-stall" % mode, body, False)
        took = time.monotonic() - t0
        check(mode, "ping: no 100 from the backend, 503 after ping=2",
              st == 503 and 1.8 < took < 4, "%s after %.2fs" % (st, took))

        st, rb, got = post("/e2e?m=final&id=%s-final" % mode, body, True)
        check(mode, "end-to-end: final response instead of 100",
              st == 417 and not got, "%s, 100 %s" % (st, got))

        # The backend keeps the connection but the client waits for a 100: no
        # body to send, the backend connection is closed instead (a 500 before
        # the local commit "mod_proxy_http: no body for a final response to a
        # client waiting for 100")
        st, rb, got = post("/e2e?m=final-ka&id=%s-final-ka" % mode, body, True)
        check(mode, "end-to-end: final response, connection kept",
              st == 417 and not got, "%s, 100 %s" % (st, got))
        st, rb, got = post("/e2e?d1=0&d2=0&id=%s-after-ka" % mode, body, True)
        check(mode, "  next request (backend connection reused)",
              st == 200 and rb == digest(body), "%s" % st)

        # The same with ping= (the client doesn't wait for a 100): the body is
        # sent for the backend to keep the connection, async before
        # processing the final response (its head pre-read)
        before = errlog("final response instead of 100 Continue")
        st, rb, got = post("/ping?m=final-ka&id=%s-ping-final-ka" % mode, body, False)
        early = errlog("final response instead of 100 Continue") - before
        # The backend records the body after sending the 417, which the client
        # may get first: wait for it (up to 2s)
        deadline = time.monotonic() + 2
        while ("%s-ping-final-ka" % mode) not in final_body and time.monotonic() < deadline:
            time.sleep(0.01)
        sent = final_body.get("%s-ping-final-ka" % mode)
        check(mode, "ping: final response, connection kept, body sent",
              st == 417 and sent == len(body) and early == (mode == "async"),
              "%s, body %s/%d sent, %s" % (st, sent, len(body),
                                          "before processing" if early else "when processing"))
        st, rb, got = post("/ping?d1=0&d2=0&id=%s-ping-after-ka" % mode, body, False)
        check(mode, "  next request", st == 200 and rb == digest(body), "%s" % st)

        # The client expects a 100 that httpd itself must send (HTTP_IN, when
        # reading the body): not forwarding the backend's (Proxy100Continue
        # Off), or suppressing it (proxy-interim-response Suppress)
        for loc in ("off", "suppress"):
            t0 = time.monotonic()
            st, rb, got = post("/%s?d1=0.5&d2=0.5&id=%s-%s" % (loc, mode, loc), body, True)
            took = time.monotonic() - t0
            check(mode, "client expects 100, %s" % loc,
                  st == 200 and got and rb == digest(body) and took < 5,
                  "%s, 100 %s, %.2fs" % (st, got, took))

        # 6 concurrent uploads on 2 threads, the backend taking 1s for the
        # 100 and 1s for the response: the async ones shouldn't hold a thread
        results = [None] * 6

        def one(i):
            results[i] = post("/e2e?d1=1&d2=1&id=%s-c%d" % (mode, i), body, True)
        t0 = time.monotonic()
        ths = [threading.Thread(target=one, args=(i,)) for i in range(6)]
        for t in ths:
            t.start()
        for t in ths:
            t.join()
        took = time.monotonic() - t0
        ok = all(r and r[0] == 200 and r[1] == digest(body) for r in results)
        if mode == "async":
            ok = ok and took < 3
        check(mode, "6 concurrent, 2 threads, backend 1s+1s",
              ok, "%.2fs, statuses %s" % (took, [r[0] if r else None for r in results]))

        # 2 concurrent uploads with ~7MB of headers (more than the socket
        # buffers can take, up to 4MB on Linux), the backend (small receive
        # buffer) not reading them for 3s: async, writing the head before the
        # 100 waits for the backend in the MPM, then the body follows the 100
        # (the times are mostly moving 7MB heads, not telling)
        pad = b"".join(b"X-Pad-%03d: %s\r\n" % (k, b"p" * 8000) for k in range(900))
        results = [None] * 2
        before = errlog("request: waiting for the backend (async)")

        def big(i):
            results[i] = post("/slowhead?d1=0&d2=0&id=%s-h%d" % (mode, i), body, True,
                              pad)
        ths = [threading.Thread(target=big, args=(i,)) for i in range(2)]
        for t in ths:
            t.start()
        for t in ths:
            t.join()
        waits = errlog("request: waiting for the backend (async)") - before
        ok = all(r and r[0] == 200 and r[1] == digest(body) for r in results)
        ok = ok and ((waits > 0) == (mode == "async"))
        check(mode, "2 concurrent, big head read after 3s",
              ok, "statuses %s, head waits %d"
              % ([r[0] if r else None for r in results], waits))

        check(mode, "error_log: no crash", errlog("exit signal") + errlog("AH00052") == 0, "")
    finally:
        stop(p)

sys.exit(0 if all(report) else 1)
