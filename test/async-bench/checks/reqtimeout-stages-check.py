"""Audit mod_reqtimeout's stages with the event MPM: handshake, header (with
minrate and a max), keepalive to the next request (pipelined, or a TLS record
split across TCP segments), and the module loaded but disabled. Run it against
several installs to compare (e.g. this tree and plain trunk).

usage: python3 -I reqtimeout-stages-check.py HTTPD_PREFIX WORKDIR
"""

import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import time

prefix, work = sys.argv[1], sys.argv[2]
os.makedirs(work, exist_ok=True)
HTTP, HTTPS = 18440, 18441

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{http}
Listen 127.0.0.1:{https} https
PidFile "{work}/httpd.pid"
ErrorLog "{work}/error_log"
LogLevel warn{rt_log}
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
{load_rt}LoadModule reqtimeout_module modules/mod_reqtimeout.so
LoadModule ssl_module modules/mod_ssl.so
ServerName localhost
StartServers 1
ThreadsPerChild 4
MaxRequestWorkers 4
Timeout {timeout}
KeepAliveTimeout 10
# No TCP_DEFER_ACCEPT: with it (the default "data" on Linux) the kernel holds a
# connection that sends nothing for ~30s before httpd accepts it, so the
# handshake stage only starts then
AcceptFilter http none
AcceptFilter https none
DocumentRoot "{work}"
{rt}
<VirtualHost 127.0.0.1:{https}>
    SSLEngine on
    SSLCertificateFile "{cert}"
    SSLCertificateKeyFile "{key}"
</VirtualHost>
"""

cert, key = os.path.join(work, "cert.pem"), os.path.join(work, "key.pem")
if not os.path.exists(cert):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=127.0.0.1"],
                   check=True, capture_output=True)
with open(os.path.join(work, "index.html"), "w") as f:
    f.write("hello\n")


def start(rt, timeout=30, load_rt=True):
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(CONF.format(prefix=prefix, http=HTTP, https=HTTPS, work=work, rt=rt,
                            cert=cert, key=key, timeout=timeout,
                            load_rt="" if load_rt else "#",
                            rt_log=" reqtimeout:info" if load_rt else ""))
    open(os.path.join(work, "error_log"), "w").close()
    p = subprocess.Popen([os.path.join(prefix, "bin", "httpd"), "-f",
                          os.path.join(work, "httpd.conf"), "-DFOREGROUND"])
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", HTTP), 0.2).close()
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


def errlog():
    with open(os.path.join(work, "error_log")) as f:
        return f.read()


def until_closed(s, limit=40):
    """Read until the server closes; returns (data, seconds)."""
    t0 = time.monotonic()
    s.settimeout(limit)
    data = b""
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            data += b
    except (socket.timeout, ConnectionResetError, ssl.SSLError, OSError):
        pass
    return data, time.monotonic() - t0


def status_of(data):
    m = re.match(rb"HTTP/1.1 (\d+)", data)
    return int(m.group(1)) if m else None


report = []


def check(name, ok, detail):
    report.append(ok)
    print("%-58s %s  %s" % (name, "OK  " if ok else "FAIL", detail))
    sys.stdout.flush()


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# 1. Header stalled, 2. header minrate with a max
p = start("RequestReadTimeout handshake=3 header=3 body=3")
try:
    s = socket.create_connection(("127.0.0.1", HTTP), 10)
    s.sendall(b"GET /index.html HTTP/1.1\r\nHost: x\r\n")
    data, took = until_closed(s)
    s.close()
    log = errlog()
    logged = log.count("Request header read timeout")
    check("header stalled: 408 at header=3s, AH01382", 2.5 < took < 5
          and status_of(data) == 408 and logged == 1,
          "%.1fs, status %s, AH01382 header %d" % (took, status_of(data), logged))

    # 5. handshake: nothing sent, then half a ClientHello
    s = socket.create_connection(("127.0.0.1", HTTPS), 10)
    data, took = until_closed(s)
    s.close()
    check("handshake, nothing sent: closed at handshake=3s", 2.5 < took < 5,
          "%.1fs, AH01382 handshake %d" % (took, errlog().count("Request handshake read timeout")))
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = out.read()
    s = socket.create_connection(("127.0.0.1", HTTPS), 10)
    s.sendall(hello[:len(hello) // 2])
    data, took = until_closed(s)
    s.close()
    check("handshake, half a ClientHello: closed at handshake=3s", 2.5 < took < 5,
          "%.1fs, AH01382 handshake %d" % (took, errlog().count("Request handshake read timeout")))

    # 6. pipelined requests on a kept-alive connection
    s = socket.create_connection(("127.0.0.1", HTTP), 10)
    s.sendall(b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n")
    s.settimeout(5)
    data = s.recv(65536)
    s.sendall(b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n" * 2)
    data = b""
    t0 = time.monotonic()
    while data.count(b"hello") < 2 and time.monotonic() - t0 < 5:
        try:
            data += s.recv(65536)
        except socket.timeout:
            break
    s.close()
    check("keepalive then 2 pipelined requests: both served", data.count(b"hello") == 2,
          "%d responses" % data.count(b"hello"))

    # 4. TLS keepalive, the next request's record split across TCP segments
    raw = socket.create_connection(("127.0.0.1", HTTPS), 10)
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out)
    raw.settimeout(5)
    while True:
        try:
            obj.do_handshake()
            break
        except ssl.SSLWantReadError:
            if out.pending:
                raw.sendall(out.read())
            inc.write(raw.recv(65536))
    if out.pending:
        raw.sendall(out.read())

    def tls_get(split):
        obj.write(b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n")
        rec = out.read()
        if split:
            raw.sendall(rec[:10])
            time.sleep(1)
            raw.sendall(rec[10:])
        else:
            raw.sendall(rec)
        got = b""
        t0 = time.monotonic()
        while b"hello" not in got and time.monotonic() - t0 < 8:
            try:
                b = raw.recv(65536)
            except (socket.timeout, OSError):
                break
            if not b:
                break
            inc.write(b)
            try:
                while True:
                    got += obj.read(65536)
            except (ssl.SSLWantReadError, ssl.SSLZeroReturnError, ssl.SSLError):
                pass
        return got

    first = tls_get(False)
    second = tls_get(True)
    raw.close()
    check("TLS keepalive, next request's record split (1s gap)",
          b"hello" in first and b"hello" in second,
          "first %s, second %s" % (b"hello" in first, b"hello" in second))
finally:
    stop(p)
crashes = errlog().count("exit signal")
check("error_log: no crash (stages)", crashes == 0, "")

# 2. header minrate with a max: too slow cut at 2s, fast enough capped at 4s
p = start("RequestReadTimeout header=2-4,minrate=100 body=3")
try:
    # One "X-Pad: a...\r\n" line (9 + chunk bytes) every `gap` seconds
    # (not kept: each line still extends the deadline a bit, so it's cut
    # between the initial 2s and the max 4s, around 3s)
    for name, chunk, gap, lo, hi in (("header minrate not kept (20 B/s): cut before max=4s", 1, 0.5, 2.5, 3.9),
                                     ("header minrate kept (290 B/s): capped at max=4s", 20, 0.1, 3.5, 6)):
        s = socket.create_connection(("127.0.0.1", HTTP), 10)
        s.sendall(b"GET /index.html HTTP/1.1\r\n")
        t0 = time.monotonic()
        s.setblocking(False)
        closed = None
        while time.monotonic() - t0 < 10:
            try:
                s.sendall(b"X-Pad: " + b"a" * chunk + b"\r\n")
            except (BlockingIOError, OSError):
                pass
            try:
                # The server's answer (a 408) or its close, whichever first
                b = s.recv(65536)
                closed = time.monotonic() - t0
                break
            except BlockingIOError:
                pass
            except OSError:
                closed = time.monotonic() - t0
                break
            time.sleep(gap)
        s.close()
        check(name, closed is not None and lo < closed < hi,
              "%s" % ("%.1fs" % closed if closed is not None else "not closed in 10s"))
finally:
    stop(p)

# 3. loaded but disabled for the vhost
p = start("RequestReadTimeout header=0 body=0")
try:
    s = socket.create_connection(("127.0.0.1", HTTP), 10)
    s.sendall(b"GET /index.html HTTP/1.1\r\n")
    time.sleep(1)
    s.sendall(b"Host: x\r\n\r\n")
    s.settimeout(5)
    try:
        data = s.recv(65536)
    except OSError:
        data = b""
    s.close()
    time.sleep(0.5)
    log = errlog()
    check("module disabled (header=0 body=0), slow header: served",
          b"hello" in data and log.count("exit signal") == 0,
          "%s, crash %d" % (status_of(data), log.count("exit signal")))
finally:
    stop(p)

# mod_reqtimeout's deadline later than the server's Timeout: the 408 at Timeout
p = start("RequestReadTimeout header=10 body=10", timeout=3)
try:
    s = socket.create_connection(("127.0.0.1", HTTP), 10)
    s.sendall(b"GET /index.html HTTP/1.1\r\nHost: x\r\n")
    data, took = until_closed(s)
    s.close()
    check("header=10 capped at Timeout=3s, header stalled: 408 at 3s",
          2.5 < took < 5 and status_of(data) == 408,
          "%.1fs, status %s" % (took, status_of(data)))
finally:
    stop(p)

# Without mod_reqtimeout: the server's Timeout applies to the header
p = start("", timeout=3, load_rt=False)
try:
    s = socket.create_connection(("127.0.0.1", HTTP), 10)
    s.sendall(b"GET /index.html HTTP/1.1\r\nHost: x\r\n")
    data, took = until_closed(s)
    s.close()
    check("no mod_reqtimeout, header stalled: 408 at Timeout=3s",
          2.5 < took < 5 and status_of(data) == 408,
          "%.1fs, status %s" % (took, status_of(data)))
finally:
    stop(p)

sys.exit(0 if all(report) else 1)
