"""Check the nonblocking backend connect of the prototype.

usage: MODES="sync async" python3 -I async-connect-check.py HTTPD_PREFIX WORKDIR
"""

import http.client
import os
import socket
import sys
import threading
import time

here = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(here, "async-proto-check.py")).read()
exec(src.split("report = []")[0])

BACKLOG = 18433
CONF += """
<Location "/backlog">
    ProxyPass "http://127.0.0.1:{backlog}/backlog" retry=1ms
    {asyncconf}
</Location>
<Location "/blackhole">
    ProxyPass "http://192.0.2.1:{backlog}/blackhole" retry=1ms connectiontimeout=1
    {asyncconf}
</Location>
<Location "/failover">
    ProxyPass "http://localhost:{backend}/slow" retry=1ms
    {asyncconf}
</Location>
""".replace("{backlog}", str(BACKLOG))


class Backlog:
    """A backend whose accept queue is full until accepting() is called:
    connects to it are in progress (SYNs dropped) until then."""

    def __init__(self):
        self.ls = socket.socket()
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind(("127.0.0.1", BACKLOG))
        self.ls.listen(1)
        self.fillers = []
        for _ in range(2):
            f = socket.socket()
            f.setblocking(False)
            try:
                f.connect(("127.0.0.1", BACKLOG))
            except BlockingIOError:
                pass
            self.fillers.append(f)
        time.sleep(0.1)

    def accepting(self):
        for f in self.fillers:
            f.close()
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                s, _ = self.ls.accept()
            except OSError:
                return
            threading.Thread(target=self.one, args=(s,), daemon=True).start()

    def one(self, s):
        data = b""
        s.settimeout(5)
        try:
            while b"\r\n\r\n" not in data:
                d = s.recv(4096)
                if not d:
                    return
                data += d
            path = data.split(b" ", 2)[1]
            body = b"backlog " + path + b"\n"
            s.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n"
                      b"Content-Length: %d\r\n\r\n%s" % (len(body), body))
        except OSError:
            pass
        finally:
            s.close()

    def close(self):
        try:
            self.ls.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.ls.close()


def timed(path, res, i, t0):
    try:
        st, body = get(path, timeout=30)
    except Exception as e:
        st, body = type(e).__name__, b""
    res[i] = (st, round(time.monotonic() - t0, 2), body)


def backlog_run():
    """4 requests connecting to the full backlog (accepting after 1.5s), and
    6 fast requests to the other backend meanwhile."""
    bl = Backlog()
    slow, fast = [None] * 4, [None] * 6
    t0 = time.monotonic()
    th = [threading.Thread(target=timed, args=("/backlog?i=%d" % i, slow, i, t0))
          for i in range(4)]
    for t in th:
        t.start()
    time.sleep(0.2)
    th2 = [threading.Thread(target=timed, args=("/slow?d=0&f=%d" % i, fast, i, t0))
           for i in range(6)]
    for t in th2:
        t.start()
    time.sleep(1.3)
    bl.accepting()
    for t in th + th2:
        t.join()
    bl.close()
    return slow, fast


def blackhole_run():
    """2 requests to an unreachable backend (connectiontimeout=1), and 4 fast
    requests meanwhile."""
    slow, fast = [None] * 2, [None] * 4
    t0 = time.monotonic()
    th = [threading.Thread(target=timed, args=("/blackhole?i=%d" % i, slow, i, t0))
          for i in range(2)]
    for t in th:
        t.start()
    time.sleep(0.2)
    th2 = [threading.Thread(target=timed, args=("/slow?d=0&b=%d" % i, fast, i, t0))
           for i in range(4)]
    for t in th2:
        t.start()
    for t in th + th2:
        t.join()
    return slow, fast


def connect_findings():
    with open(os.path.join(work, "error_log")) as f:
        log = f.read()
    return {
        "connecting (async)": log.count("(async)") and log.count("connecting to "),
        "connect ready": log.count("connect ready (async)"),
        "connect timeout": log.count("connect timeout (async)"),
        "crashes": log.count("exit signal"),
    }


report = []
MODES = {"sync": "ProxyAsyncDelay -1", "async": "ProxyAsyncDelay 0\n    ProxyAsyncIdleTimeout 2"}
for mode in os.environ.get("MODES", "sync async").split():
    p = start(MODES[mode])
    try:
        slow, fast = backlog_run()
        report.append("%s: backlog: slow %s" % (mode, [(s, t) for s, t, b in slow]))
        report.append("%s: backlog: fast max %.2fs %s" % (
            mode, max(t for s, t, b in fast), [s for s, t, b in fast]))
        report.append("%s: backlog bodies ok: %s" % (
            mode, all(b"i=%d" % i in b for i, (s, t, b) in enumerate(slow))))
        slow, fast = blackhole_run()
        report.append("%s: blackhole: slow %s" % (mode, [(s, t) for s, t, b in slow]))
        report.append("%s: blackhole: fast max %.2fs %s" % (
            mode, max(t for s, t, b in fast), [s for s, t, b in fast]))
        st, body = get("/failover?d=0&x=1")
        report.append("%s: failover ::1 -> 127.0.0.1: %s %s" % (mode, st, b"x=1" in body))
        report.append("%s: error_log: %s %s" % (mode, log_findings(), connect_findings()))
    finally:
        report.append("%s: %s" % (mode, stop(p)))
backend.shutdown()
print("\n".join(report))
