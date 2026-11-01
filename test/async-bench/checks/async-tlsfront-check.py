"""Check mod_ssl's client connections not holding workers: a client
connecting and sending nothing (or a part of its ClientHello) until the
handshake times out, a client that stops reading the server's handshake
flight, a slow TLS download of a large static file (EnableMMAP on), and a
TLS backend that stops reading the proxy's handshake flight (its client
certificate). The handshake flights are made large with a certificate
carrying many subjectAltNames, the socket buffers small (SendBufferSize, the
peers' SO_RCVBUF). On loopback the proxy's socket to the backend gets a send
buffer large enough for its flight (autotuned from the 64KB MSS, no
SendBufferSize there), so its handshake can't be left pending (only
completed with a large flight and the backend stalling).

usage: MODES="sync async" python3 -I async-tlsfront-check.py HTTPD_PREFIX WORKDIR
"""

import os
import socket
import ssl
import subprocess
import threading
import time

here = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(here, "async-proto-check.py")).read().split("\nreport = []")[0])

TLSF, BK = 18436, 18437
os.makedirs(os.path.join(work, "htdocs"), exist_ok=True)
with open(os.path.join(work, "htdocs", "big.bin"), "wb") as f:
    f.write(b"b" * (8 << 20))
with open(os.path.join(work, "htdocs", "small.txt"), "wb") as f:
    f.write(b"small\n")

# A certificate of some 40KB (subjectAltNames), for the flights: less than
# FlushMaxThreshold, more than the socket buffers.
cert, key = os.path.join(work, "bigcert.pem"), os.path.join(work, "bigkey.pem")
both = os.path.join(work, "bigboth.pem")
if not os.path.exists(both):
    sans = ",".join("DNS:n%04d.flight.example.test" % i for i in range(1300))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=127.0.0.1",
                    "-addext", "subjectAltName=" + sans],
                   check=True, capture_output=True)
    with open(both, "w") as f:
        f.write(open(cert).read() + open(key).read())
CERT_SIZE = os.path.getsize(cert)

CONF = CONF.replace("LoadModule proxy_module",
                    "LoadModule ssl_module modules/mod_ssl.so\nLoadModule proxy_module")
CONF = CONF.replace("LogLevel warn proxy_http:trace5",
                    "LogLevel warn proxy_http:trace5 ssl:trace6")
CONF = CONF.replace("ServerName localhost", """ServerName localhost
Timeout 2
# Silent clients reach httpd at once (no TCP_DEFER_ACCEPT)
AcceptFilter http none
AcceptFilter https none
SendBufferSize 8192
EnableMMAP on
DocumentRoot "{work}/htdocs"
SSLProxyEngine on
SSLProxyVerify none
SSLProxyCheckPeerName off
SSLProxyCheckPeerExpire off
SSLProxyMachineCertificateFile "{work}/bigboth.pem"
<Location "/stallbk">
    ProxyPass "https://127.0.0.1:%d/stallbk" timeout=3
    {asyncconf}
</Location>
Listen 127.0.0.1:%d
<VirtualHost 127.0.0.1:%d>
    SSLEngine on
    SSLCertificateFile "{work}/bigcert.pem"
    SSLCertificateKeyFile "{work}/bigkey.pem"
</VirtualHost>""" % (BK, TLSF, TLSF))

tlsctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
tlsctx.check_hostname = False
tlsctx.verify_mode = ssl.CERT_NONE


def small_rcvbuf_socket(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    s.settimeout(30)
    s.connect(("127.0.0.1", port))
    return s


def tls_get(path, timeout=30):
    """A TLS request on a new connection: (status, body length)"""
    c = http.client.HTTPSConnection("127.0.0.1", TLSF, timeout=timeout, context=tlsctx)
    try:
        c.request("GET", path)
        r = c.getresponse()
        return r.status, len(r.read())
    except (http.client.HTTPException, OSError) as e:
        return type(e).__name__, 0
    finally:
        c.close()


def safely(get_fn, path, **kw):
    try:
        return get_fn(path, **kw)
    except (http.client.HTTPException, OSError) as e:
        return type(e).__name__, b""


def fast_meanwhile(get_fn, path, delay, n=4):
    """n requests `delay` seconds from now: the longest time, the statuses"""
    time.sleep(delay)
    res = [None] * n

    def one(i):
        t0 = time.monotonic()
        st = safely(get_fn, "%s%sf=%d" % (path, "&" if "?" in path else "?", i))[0]
        res[i] = (st, time.monotonic() - t0)
    ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return round(max(t for st, t in res), 2), sorted(set(str(st) for st, t in res))


def silent(res, i, send):
    """Connect to the TLS port, send `send` (nothing, or a part of a
    ClientHello), then wait for the server to close: seconds until closed."""
    t0 = time.monotonic()
    try:
        s = small_rcvbuf_socket(TLSF)
        if send:
            s.sendall(send)
        while s.recv(4096):
            pass
    except OSError:
        pass
    res[i] = round(time.monotonic() - t0, 2)


def client_hello():
    inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = tlsctx.wrap_bio(inb, outb)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outb.read()


def flight_stall(res, i, stall):
    """Send a ClientHello and don't read the server's flight for `stall`
    seconds (a small receive buffer): seconds until closed, bytes read."""
    t0 = time.monotonic()
    got = 0
    try:
        s = small_rcvbuf_socket(TLSF)
        s.sendall(client_hello())
        time.sleep(stall)
        while True:
            b = s.recv(65536)
            if not b:
                break
            got += len(b)
    except OSError:
        pass
    res[i] = (round(time.monotonic() - t0, 2), got)


def download_stall(res, i, stall, first=65536):
    """GET /big.bin over TLS, read `first` bytes, nothing for `stall` seconds,
    then the rest: (status line, body bytes, close_notify received,
    seconds)."""
    t0 = time.monotonic()
    got, head, notify = 0, b"", False
    try:
        s = tlsctx.wrap_socket(small_rcvbuf_socket(TLSF))
        s.sendall(b"GET /big.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        data = b""
        while b"\r\n\r\n" not in data:
            data += s.recv(16384)
        head, rest = data.split(b"\r\n\r\n", 1)
        got = len(rest)
        while got < first:
            got += len(s.recv(16384))
        time.sleep(stall)
        while True:
            b = s.recv(65536)
            if not b:
                notify = True
                break
            got += len(b)
    except (OSError, ssl.SSLError):
        pass
    res[i] = (head.split(b"\r\n", 1)[0].decode(), got, notify,
              round(time.monotonic() - t0, 2))


class StallingBackend:
    """A TLS backend that reads the proxy's ClientHello, sends its flight
    (asking for a client certificate) and then stops reading for `stall`
    seconds before closing (a small receive buffer)."""

    def __init__(self, stall):
        self.stall = stall
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.ctx.load_verify_locations(cafile=cert)
        self.ctx.verify_mode = ssl.CERT_OPTIONAL
        self.ls = socket.socket()
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        self.ls.bind(("127.0.0.1", BK))
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
            inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
            obj = self.ctx.wrap_bio(inb, outb, server_side=True)
            inb.write(s.recv(65536))
            try:
                obj.do_handshake()
            except ssl.SSLWantReadError:
                pass
            s.sendall(outb.read())
            time.sleep(self.stall)
        except (OSError, ssl.SSLError):
            pass
        finally:
            s.close()


def ssl_log_findings():
    with open(os.path.join(work, "error_log")) as f:
        log = f.read()
    return {
        "handshake wants to write": log.count("Want write during nonblocking accept"),
        "handshake output pending (async)": log.count("SSL handshake output pending"),
        "aborted at close": log.count("SSL handshake not completed at close"),
        "backend handshake waits to write (async)": log.count("waiting to write (async)"),
        "crashes": log.count("exit signal"),
    }


sb = StallingBackend(4)
report = []
MODES = {"sync": "ProxyAsyncDelay -1", "async": "ProxyAsyncDelay 0"}
for mode in os.environ.get("MODES", "sync async").split():
    p = start(MODES[mode])
    try:
        report.append("%s: certificate %d bytes" % (mode, CERT_SIZE))
        # Clients sending nothing, or a part of a ClientHello, until the
        # handshake times out (Timeout 2); 4 fast requests after 2.5s.
        res = [None] * 4
        hello = client_hello()
        ts = [threading.Thread(target=silent, args=(res, i, b"" if i < 2 else hello[:20]))
              for i in range(4)]
        for t in ts:
            t.start()
        fast = fast_meanwhile(tls_get, "/small.txt", 2.5)
        for t in ts:
            t.join()
        report.append("%s: 4 clients silent in the handshake (2 sending nothing, 2 a part of "
                      "a ClientHello), Timeout 2, 2 workers: closed after %s; 4 fast TLS "
                      "requests at 2.5s (max time, statuses): %s" % (mode, res, fast))
        # Clients not reading the server's flight (Timeout 2)
        res = [None] * 4
        ts = [threading.Thread(target=flight_stall, args=(res, i, 3)) for i in range(4)]
        for t in ts:
            t.start()
        fast = fast_meanwhile(tls_get, "/small.txt", 1)
        for t in ts:
            t.join()
        report.append("%s: 4 clients not reading the server's handshake flight for 3s "
                      "(Timeout 2): (closed after, bytes read) %s; 4 fast TLS requests at 1s "
                      "(max time, statuses): %s" % (mode, res, fast))
        # Slow downloads of a large static file
        res = [None] * 2
        ts = [threading.Thread(target=download_stall, args=(res, i, 3)) for i in range(2)]
        for t in ts:
            t.start()
        fast = fast_meanwhile(tls_get, "/small.txt", 1)
        for t in ts:
            t.join()
        report.append("%s: 2 TLS downloads of an 8MB static file stalling 3s (EnableMMAP on): "
                      "%s; 4 fast TLS requests at 1s (max time, statuses): %s"
                      % (mode, res, fast, ))
        # A TLS backend not reading the proxy's flight (its client certificate)
        res = [None] * 4

        def via_stalling(i):
            t0 = time.monotonic()
            res[i] = (safely(get, "/stallbk?i=%d" % i, timeout=30)[0],
                      round(time.monotonic() - t0, 2))
        ts = [threading.Thread(target=via_stalling, args=(i,)) for i in range(4)]
        for t in ts:
            t.start()
        fast = fast_meanwhile(get, "/slow?d=0", 1)
        for t in ts:
            t.join()
        report.append("%s: 4 requests to a TLS backend not reading the proxy's handshake "
                      "flight (timeout=3): %s; 4 fast plain requests at 1s (max time, "
                      "statuses): %s" % (mode, res, fast))
        report.append("%s: error_log: %s" % (mode, ssl_log_findings()))
    finally:
        report.append("%s: %s" % (mode, stop(p)))
        os.replace(os.path.join(work, "error_log"), os.path.join(work, "error_log." + mode))
backend.shutdown()
print("\n".join(report))
