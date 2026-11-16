"""Check the nonblocking TLS handshake with the backend.

usage: MODES="sync async" python3 -I async-tls-check.py HTTPD_PREFIX WORKDIR
"""

import os
import socket
import ssl
import subprocess
import threading
import time

here = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(here, "async-proto-check.py")).read().split("\nreport = []")[0])

TLS = 18434
CONF = CONF.replace("LoadModule proxy_module",
                    "LoadModule ssl_module modules/mod_ssl.so\nLoadModule proxy_module")
CONF = CONF.replace("LogLevel warn proxy_http:trace5",
                    "LogLevel warn proxy_http:trace5 ssl:info")
CONF += """
SSLProxyEngine on
SSLProxyVerify none
SSLProxyCheckPeerName off
SSLProxyCheckPeerExpire off
<Location "/tls">
    ProxyPass "https://127.0.0.1:%d/tls" timeout=3
    {asyncconf}
</Location>
<Location "/new">
    ProxyPass "https://127.0.0.1:%d/new" timeout=3 disablereuse=on
    {asyncconf}
</Location>
""" % (TLS, TLS)

cert, key = os.path.join(work, "cert.pem"), os.path.join(work, "key.pem")
if not os.path.exists(cert):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=127.0.0.1"],
                   check=True, capture_output=True)


class TlsBackend:
    """mode: 'ok' (handshake after `delay`), 'plain' (no TLS: answers HTTP in
    clear), 'stall' (never handshakes). Records whether a request came in clear."""

    def __init__(self):
        self.mode, self.delay, self.cleartext = "ok", 0, False
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.ls = socket.socket()
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind(("127.0.0.1", TLS))
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
        try:
            s.settimeout(10)
            if self.mode == "stall":
                time.sleep(8)
                return
            if self.mode == "plain":
                data = s.recv(4096)
                if data.startswith((b"GET ", b"POST ")):
                    self.cleartext = True
                s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nplain\n")
                time.sleep(0.5)
                return
            time.sleep(self.delay)
            t = self.ctx.wrap_socket(s, server_side=True)
            while True:
                data = b""
                while b"\r\n\r\n" not in data:
                    d = t.recv(4096)
                    if not d:
                        return
                    data += d
                body = b"tls " + data.split(b" ", 2)[1] + b"\n"
                t.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
        except (OSError, ssl.SSLError):
            pass
        finally:
            s.close()


tb = TlsBackend()


def timed(path, res, i, t0):
    try:
        st, body = get(path, timeout=30)
    except Exception as e:
        st, body = type(e).__name__, b""
    res[i] = (st, round(time.monotonic() - t0, 2), body)


report = []
MODES = {"sync": "ProxyAsyncDelay -1", "async": "ProxyAsyncDelay 0\n    ProxyAsyncIdleTimeout 2"}
for mode in os.environ.get("MODES", "sync async").split():
    p = start(MODES[mode])
    try:
        # 4 slow handshakes (1s), 6 fast plain requests meanwhile
        tb.mode, tb.delay = "ok", 1
        slow, fast = [None] * 4, [None] * 6
        t0 = time.monotonic()
        th = [threading.Thread(target=timed, args=("/tls?i=%d" % i, slow, i, t0)) for i in range(4)]
        for t in th:
            t.start()
        time.sleep(0.2)
        th2 = [threading.Thread(target=timed, args=("/slow?d=0&f=%d" % i, fast, i, t0)) for i in range(6)]
        for t in th2:
            t.start()
        for t in th + th2:
            t.join()
        report.append("%s: 4 slow TLS handshakes (1s): %s, bodies ok %s" % (
            mode, [(s, t) for s, t, b in slow],
            all(b"i=%d" % i in b for i, (s, t, b) in enumerate(slow))))
        report.append("%s: 6 fast plain requests meanwhile: max %.2fs %s" % (
            mode, max(t for s, t, b in fast) - 0.2, sorted(set(s for s, t, b in fast))))
        # keepalive: the TLS connection reused (no new handshake)
        tb.delay = 0
        c = http.client.HTTPConnection("127.0.0.1", FRONT, timeout=20)
        seq = [get("/tls?k=%d" % i, conn=c)[0] for i in range(3)]
        c.close()
        report.append("%s: keepalive, 3 requests: %s" % (mode, seq))
        # handshake failure: plain HTTP on the TLS port
        tb.mode, tb.cleartext = "plain", False
        t0 = time.monotonic()
        st, _ = get("/new?x=plain")
        report.append("%s: backend not TLS: %s after %.1fs, request sent in clear: %s"
                      % (mode, st, time.monotonic() - t0, tb.cleartext))
        # handshake stall (timeout=3, ProxyAsyncIdleTimeout 2 when async)
        tb.mode = "stall"
        t0 = time.monotonic()
        st, _ = get("/new?x=stall")
        report.append("%s: handshake stalls: %s after %.1fs" % (mode, st, time.monotonic() - t0))
        tb.mode = "ok"
        with open(os.path.join(work, "error_log")) as f:
            log = f.read()
        report.append("%s: handshake waits (async) %d, crashes %d" % (
            mode, log.count("TLS handshake with 127.0.0.1:%d: waiting" % TLS),
            log.count("exit signal")))
    finally:
        report.append("%s: %s" % (mode, stop(p)))
backend.shutdown()
print("\n".join(report))
