"""Check mod_proxy's tunnels: mod_proxy_http's (Upgrade, e.g. WebSocket),
blocking ("sync", ProxyAsyncDelay -1), async by default ("default") and async
(ProxyAsyncDelay 0, ProxyAsyncIdleTimeout), mod_proxy_wstunnel's ("wstunnel",
ProxyWebsocketFallbackToProxyHttp Off) and mod_proxy_connect's ("connect", the
same Upgrade through a CONNECT tunnel): tunnels exchanging data, many on few
threads, the idle timeout, either side closing, and a large transfer to a slow
client.

usage: MODES="sync default async wstunnel connect" python3 -I async-tunnel-check.py HTTPD_PREFIX WORKDIR
"""

import os
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

prefix, work = sys.argv[1], sys.argv[2]
os.makedirs(work, exist_ok=True)
BACKEND, FRONT = 18431, 18432
IDLE = 2
BIG = 2 * 1024 * 1024
backend_closed = {}  # id -> when the backend saw the client's side close


def backend_conn(s):
    """101 for the Upgrade (after 1s with "slow"), then: "echo" (and "slow")
    echoes, "big" sends BIG bytes, "close" closes; "deny" answers a 403 after
    0.5s instead of the 101; "early" answers the 101 right away without the
    100 Continue the request expects (RFC 9110 7.8 violation); records when
    the peer closes."""
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            b = s.recv(4096)
            if not b:
                return
            data += b
        head, rest = data.split(b"\r\n\r\n", 1)
        m = re.search(rb"(?:GET|POST) /ws\?id=([^& ]+)(?:&m=(\w+))? ", head)
        tag, mode = m.group(1).decode(), (m.group(2) or b"echo").decode()
        if mode == "deny":
            time.sleep(0.5)
            s.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 7\r\n"
                      b"Connection: close\r\n\r\ndenied\n")
            return
        if mode == "slow":
            time.sleep(1)
            mode = "echo"
        s.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                  b"Connection: Upgrade\r\n\r\n")
        if mode == "big":
            s.sendall(b"x" * BIG)
            s.shutdown(socket.SHUT_WR)
        elif mode == "close":
            time.sleep(0.5)
            s.close()
            return
        if rest:
            s.sendall(rest)
        while True:
            b = s.recv(65536)
            if not b:
                backend_closed[tag] = time.monotonic()
                return
            if mode == "echo":
                s.sendall(b)
    except OSError:
        pass
    finally:
        s.close()


ls = socket.socket()
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", BACKEND))
ls.listen(128)


def serve():
    while True:
        try:
            s, _ = ls.accept()
        except OSError:
            return
        threading.Thread(target=backend_conn, args=(s,), daemon=True).start()


threading.Thread(target=serve, daemon=True).start()

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{front}
PidFile "{work}/httpd.pid"
ErrorLog "{work}/error_log"
LogLevel warn proxy:trace5 proxy_http:info
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule proxy_wstunnel_module modules/mod_proxy_wstunnel.so
LoadModule proxy_connect_module modules/mod_proxy_connect.so
ServerName localhost
StartServers 1
ServerLimit 1
ThreadLimit 2
ThreadsPerChild 2
MaxRequestWorkers 2
MinSpareThreads 1
MaxSpareThreads 2
{modeconf}
"""

HTTP_LOC = """<Location "/ws">
    ProxyPass "http://127.0.0.1:{backend}/ws" upgrade=websocket max=32 timeout={idle}
    %s
</Location>"""

MODES = {"sync": HTTP_LOC % "ProxyAsyncDelay -1",
         "default": HTTP_LOC % "",
         "async": HTTP_LOC % ("ProxyAsyncDelay 0\n    ProxyAsyncIdleTimeout %d" % IDLE),
         "wstunnel": """<Location "/ws">
    ProxyPass "ws://127.0.0.1:{backend}/ws" max=32
    ProxyWebsocketFallbackToProxyHttp Off
    ProxyWebsocketIdleTimeout {idle}
</Location>""",
         "connect": """ProxyRequests On
AllowCONNECT {backend}
ProxyTimeout {idle}
Timeout {idle}"""}


def start(mode):
    modeconf = MODES[mode].format(backend=BACKEND, idle=IDLE)
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(CONF.format(prefix=prefix, work=work, front=FRONT, modeconf=modeconf))
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


def read_head(s):
    data = b""
    while b"\r\n\r\n" not in data:
        b = s.recv(4096)
        if not b:
            break
        data += b
    return data.split(b"\r\n\r\n", 1) if b"\r\n\r\n" in data else (data, b"")


def upgrade(tag, mode="echo", rcvbuf=None):
    """The Upgrade to the backend, through a CONNECT tunnel first in the
    "connect" mode (current_mode)."""
    s = socket.socket()
    if rcvbuf:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    s.settimeout(20)
    s.connect(("127.0.0.1", FRONT))
    if current_mode == "connect":
        s.sendall(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n"
                  % (BACKEND, BACKEND))
        head, _ = read_head(s)
        if not head.startswith(b"HTTP/1.0 200"):
            return s, False, b""
    s.sendall(b"GET /ws?id=%s&m=%s HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
              b"Connection: Upgrade\r\n\r\n" % (tag.encode(), mode.encode()))
    head, rest = read_head(s)
    heads[tag] = head
    return s, head.startswith(b"HTTP/1.1 101"), rest


heads = {}  # tag -> the response head to the Upgrade


report = []


def check(mode, name, ok, detail):
    report.append(ok)
    print("%-8s %-52s %s  %s" % (mode, name, "OK  " if ok else "FAIL", detail))
    sys.stdout.flush()


def errlog(text):
    with open(os.path.join(work, "error_log")) as f:
        return f.read().count(text)


current_mode = None
for mode in os.environ.get("MODES", "sync default async wstunnel connect").split():
    current_mode = mode
    p = start(mode)
    try:
        # 6 tunnels on 2 threads, 4 messages each 0.5s apart
        results = [None] * 6

        def one(i):
            s, ok, _ = upgrade("%s-c%d" % (mode, i))
            got = 0
            s.settimeout(15)
            for k in range(4):
                msg = b"ping %d %d\n" % (i, k)
                s.sendall(msg)
                data = b""
                while len(data) < len(msg):
                    b = s.recv(4096)
                    if not b:
                        break
                    data += b
                got += (data == msg)
                time.sleep(0.5)
            s.close()
            results[i] = ok and got == 4
        t0 = time.monotonic()
        ths = [threading.Thread(target=one, args=(i,)) for i in range(6)]
        for t in ths:
            t.start()
        for t in ths:
            t.join()
        took = time.monotonic() - t0
        ok = all(results) and (took < 4 if mode != "sync" else True)
        check(mode, "6 tunnels, 2 threads, 4 echoes 0.5s apart", ok,
              "%.1fs, all echoed: %s" % (took, all(results)))

        # 6 Upgrades on 2 threads whose backend answers the 101 after 1s:
        # waiting for it doesn't hold a thread either
        results = [None] * 6

        def slow(i):
            s, ok, _ = upgrade("%s-s%d" % (mode, i), "slow")
            s.settimeout(15)
            s.sendall(b"hello\n")
            data = b""
            while len(data) < 6:
                b = s.recv(4096)
                if not b:
                    break
                data += b
            s.close()
            results[i] = ok and data == b"hello\n"
        t0 = time.monotonic()
        ths = [threading.Thread(target=slow, args=(i,)) for i in range(6)]
        for t in ths:
            t.start()
        for t in ths:
            t.join()
        took = time.monotonic() - t0
        ok = all(results) and (took < 2 if mode != "sync" else took > 2.5)
        check(mode, "6 Upgrades, 2 threads, 101 after 1s", ok,
              "%.1fs, all switched and echoed: %s" % (took, all(results)))

        # The backend refusing the Upgrade (403 after 0.5s): forwarded
        s, ok, rest = upgrade("%s-deny" % mode, "deny")
        s.settimeout(5)
        try:
            while len(rest) < 7:
                b = s.recv(4096)
                if not b:
                    break
                rest += b
        except OSError:
            pass
        s.close()
        head = heads.get("%s-deny" % mode, b"")
        check(mode, "Upgrade refused: 403 forwarded", not ok
              and head.startswith(b"HTTP/1.1 403") and rest == b"denied\n",
              "%r %r" % (head.split(b"\r\n", 1)[0], rest))

        # The client resetting its connection before the 101 (after 1s):
        # no tunnel for nobody, nor a tunneling error logged (mod_proxy_http
        # only, the others don't read the 101)
        if mode not in ("wstunnel", "connect"):
            before = (errlog("client gone while sending the 101"), errlog("AH10221"))
            s = socket.create_connection(("127.0.0.1", FRONT), 10)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            s.sendall(b"GET /ws?id=%s-rst&m=slow HTTP/1.1\r\nHost: x\r\n"
                      b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                      % mode.encode())
            time.sleep(0.3)
            s.close()  # RST
            time.sleep(1.5)
            after = (errlog("client gone while sending the 101"), errlog("AH10221"))
            check(mode, "client reset before the 101: no tunnel",
                  after[0] == before[0] + 1 and after[1] == before[1],
                  "client gone logged %d, AH10221 %d"
                  % (after[0] - before[0], after[1] - before[1]))

        # An Upgrade with a body and Expect: 100-continue, the backend
        # switching protocols without the 100 (RFC 9110 7.8): a 502, never
        # a 101 to the client (mod_proxy_http only)
        if mode not in ("wstunnel", "connect"):
            s = socket.create_connection(("127.0.0.1", FRONT), 10)
            s.sendall(b"POST /ws?id=%s-early&m=early HTTP/1.1\r\nHost: x\r\n"
                      b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                      b"Expect: 100-continue\r\nContent-Length: 5\r\n\r\n"
                      % mode.encode())
            s.settimeout(10)
            head, _ = read_head(s)
            s.close()
            check(mode, "101 before the 100 Continue: 502",
                  head.startswith(b"HTTP/1.1 502"), "%r" % head.split(b"\r\n", 1)[0])

        # Idle: closed by the server after the idle timeout
        s, ok, _ = upgrade("%s-idle" % mode)
        t0 = time.monotonic()
        s.settimeout(IDLE + 10)
        try:
            b = s.recv(4096)
        except OSError:
            b = None
        took = time.monotonic() - t0
        s.close()
        check(mode, "idle tunnel closed at the timeout (%ds)" % IDLE,
              ok and b == b"" and IDLE - 0.5 < took < IDLE + 2, "%.1fs" % took)

        # The client closes: the backend sees it
        tag = "%s-cclose" % mode
        s, ok, _ = upgrade(tag)
        s.sendall(b"hello\n")
        s.recv(4096)
        t0 = time.monotonic()
        s.close()
        for _ in range(100):
            if tag in backend_closed:
                break
            time.sleep(0.02)
        seen = backend_closed.get(tag)
        check(mode, "client closes: backend sees it", seen is not None and seen - t0 < 1,
              "%s" % ("%.2fs" % (seen - t0) if seen else "not seen"))

        # The backend closes: the client sees it
        s, ok, _ = upgrade("%s-bclose" % mode, "close")
        s.settimeout(5)
        t0 = time.monotonic()
        try:
            b = s.recv(4096)
        except OSError:
            b = None
        took = time.monotonic() - t0
        s.close()
        check(mode, "backend closes: client sees it", b == b"" and took < 2, "%.2fs" % took)

        # 2MB to a slow reader (the tunnel waits for the client to take
        # output): a small receive buffer, 16KB read every 20ms
        before = errlog("tunnel: waiting (async)")
        s, ok, rest = upgrade("%s-big" % mode, "big", rcvbuf=16384)
        s.settimeout(30)
        n = len(rest)
        t0 = time.monotonic()
        while True:
            try:
                b = s.recv(16384)
            except OSError:
                break
            if not b:
                break
            n += len(b)
            time.sleep(0.02)
        s.close()
        waits = errlog("tunnel: waiting (async)") - before
        check(mode, "2MB to a slow reader", n == BIG and (waits > 0) == (mode != "sync"),
              "%d bytes in %.1fs, MPM waits %d" % (n, time.monotonic() - t0, waits))

        check(mode, "error_log: no crash",
              errlog("exit signal") + errlog("AH00052") == 0, "")
    finally:
        stop(p)

sys.exit(0 if all(report) else 1)
