"""Check the nonblocking CONNECT exchange with a forward proxy (ProxyRemote), in
front of the TLS backend of async-tls-check.py.

usage: MODES="sync async" python3 -I async-remote-check.py HTTPD_PREFIX WORKDIR
"""

import os
import select
import socket
import threading
import time

here = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(here, "async-tls-check.py")).read().split("\nreport = []")[0])

FWD = 18435
CONF = CONF.replace("LogLevel warn proxy_http:trace5",
                    "LogLevel warn proxy_http:trace5 proxy:trace2")
CONF += """
ProxyRemote "https://127.0.0.1:%d" "http://127.0.0.1:%d"
<Location "/remote">
    ProxyPass "https://127.0.0.1:%d/remote" timeout=3 disablereuse=on
    {asyncconf}
</Location>
""" % (TLS, FWD, TLS)


class ForwardProxy:
    """mode: 'ok' (200 after `delay`, then tunnels to the target), 'split' (the
    200 sent in pieces of 3 bytes), 'big' (a 200 with a head of 20KB), 'deny'
    (407), 'stall' (never answers). Records the CONNECT requests' lines."""

    def __init__(self):
        self.mode, self.delay, self.lines = "ok", 0, []
        self.ls = socket.socket()
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind(("127.0.0.1", FWD))
        self.ls.listen(64)
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                s, _ = self.ls.accept()
            except OSError:
                return
            threading.Thread(target=self.one, args=(s,), daemon=True).start()

    def one(self, s):
        t = None
        try:
            s.settimeout(10)
            data = b""
            while b"\r\n\r\n" not in data:
                d = s.recv(4096)
                if not d:
                    return
                data += d
            line = data.split(b"\r\n", 1)[0]
            self.lines.append(line)
            if self.mode == "stall":
                time.sleep(8)
                return
            time.sleep(self.delay)
            if self.mode == "deny":
                s.sendall(b"HTTP/1.0 407 Proxy Authentication Required\r\n"
                          b"Content-Length: 0\r\n\r\n")
                time.sleep(0.5)
                return
            host, port = line.split(b" ")[1].rsplit(b":", 1)
            t = socket.create_connection((host.decode(), int(port)), timeout=10)
            reply = b"HTTP/1.0 200 Connection established\r\n"
            if self.mode == "big":
                reply += b"".join(b"X-Pad-%d: %s\r\n" % (i, b"p" * 1000) for i in range(20))
            reply += b"\r\n"
            if self.mode == "split":
                for i in range(0, len(reply), 3):
                    s.sendall(reply[i:i + 3])
                    time.sleep(0.01)
            else:
                s.sendall(reply)
            socks = [s, t]
            while True:
                r, _, _ = select.select(socks, [], [], 10)
                if not r:
                    return
                for x in r:
                    d = x.recv(65536)
                    if not d:
                        return
                    (t if x is s else s).sendall(d)
        except OSError:
            pass
        finally:
            s.close()
            if t:
                t.close()


fp = ForwardProxy()


report = []
MODES = {"sync": "ProxyAsyncDelay -1", "async": "ProxyAsyncDelay 0\n    ProxyAsyncIdleTimeout 2"}
for mode in os.environ.get("MODES", "sync async").split():
    p = start(MODES[mode])
    try:
        # 4 slow CONNECTs (1s), 6 fast plain requests meanwhile
        fp.mode, fp.delay, fp.lines = "ok", 1, []
        slow, fast = [None] * 4, [None] * 6
        t0 = time.monotonic()
        th = [threading.Thread(target=timed, args=("/remote?i=%d" % i, slow, i, t0))
              for i in range(4)]
        for t in th:
            t.start()
        time.sleep(0.2)
        th2 = [threading.Thread(target=timed, args=("/slow?d=0&f=%d" % i, fast, i, t0))
               for i in range(6)]
        for t in th2:
            t.start()
        for t in th + th2:
            t.join()
        report.append("%s: 4 slow CONNECTs (1s): %s, bodies ok %s" % (
            mode, [(s, t) for s, t, b in slow],
            all(b"tls /remote?i=%d" % i in b for i, (s, t, b) in enumerate(slow))))
        report.append("%s: 6 fast plain requests meanwhile: max %.2fs %s" % (
            mode, max(t for s, t, b in fast) - 0.2, sorted(set(s for s, t, b in fast))))
        report.append("%s: CONNECT lines: %s" % (mode, sorted(set(fp.lines))))
        fp.delay = 0
        # the reply in pieces of 3 bytes, the end of its head straddling reads
        fp.mode = "split"
        st, body = get("/remote?x=split")
        report.append("%s: reply in pieces: %s %s" % (mode, st, b"x=split" in body))
        # a reply's head larger than the buffer (drained)
        fp.mode = "big"
        st, body = get("/remote?x=big")
        report.append("%s: reply head of 20KB: %s %s" % (mode, st, b"x=big" in body))
        # refused by the forward proxy
        fp.mode = "deny"
        t0 = time.monotonic()
        st, _ = get("/remote?x=deny")
        report.append("%s: CONNECT refused (407): %s after %.1fs" % (mode, st, time.monotonic() - t0))
        # never answered (timeout=3, ProxyAsyncIdleTimeout 2 when async)
        fp.mode = "stall"
        t0 = time.monotonic()
        st, _ = get("/remote?x=stall")
        report.append("%s: CONNECT never answered: %s after %.1fs" % (mode, st, time.monotonic() - t0))
        fp.mode = "ok"
        st, body = get("/remote?x=after")
        report.append("%s: then: %s %s" % (mode, st, b"x=after" in body))
        with open(os.path.join(work, "error_log")) as f:
            log = f.read()
        report.append("%s: CONNECT waits (async) %d, crashes %d" % (
            mode, log.count("through 127.0.0.1:%d (127.0.0.1:%d) in progress" % (FWD, FWD)),
            log.count("exit signal")))
    finally:
        report.append("%s: %s" % (mode, stop(p)))
backend.shutdown()
print("\n".join(report))
