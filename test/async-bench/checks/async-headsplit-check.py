"""Check the request heads read without blocking (AP_GETLINE_NONBLOCK), resumed
after an EAGAIN anywhere: each head is sent in one write, in two writes split
at every byte (a pause between them, so that the first read ends in EAGAIN),
and one byte per write, and every response must be the one-write response
expected.

- fields: 7 fields with LimitRequestFields 6, a 400 wherever split;
- nul: a NUL byte in a field value, a 400 wherever split;
- fold: a field folded over three lines (obs-fold), the value joined;
- lf-limit: a field line ending with a single LF exactly at
  LimitRequestFieldSize (HttpProtocolOptions Unsafe), the value whole;
- plain: a request with a few fields, a 200 and its fields.

usage: python3 -I async-headsplit-check.py HTTPD_PREFIX WORKDIR
"""

import os
import signal
import socket
import subprocess
import sys
import time

prefix, work = sys.argv[1], sys.argv[2]
os.makedirs(work, exist_ok=True)
STRICT, UNSAFE = 18442, 18443
PAUSE = 0.02          # between the two writes of a split
BYTE_PAUSE = 0.002    # between the writes of one byte each

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{strict}
Listen 127.0.0.1:{unsafe}
PidFile "{work}/httpd.pid"
ErrorLog "{work}/error_log"
LogLevel info
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule headers_module modules/mod_headers.so
ServerName localhost
StartServers 1
ServerLimit 1
ThreadsPerChild 4
MaxRequestWorkers 4
Timeout 10
LimitRequestFields 6
LimitRequestFieldSize 100
DocumentRoot "{work}/docs"
Header always set X-Echo-A "expr=%{{req:X-A}}"
Header always set X-Echo-F "expr=%{{req:X-F}}"
Header always set X-Echo-L "expr=%{{req:X-L}}"
<VirtualHost 127.0.0.1:{unsafe}>
    HttpProtocolOptions Unsafe
</VirtualHost>
"""

LONG = b"v" * 97  # "X-L: " + 97 bytes = LimitRequestFieldSize + 2 (n - 1)
CASES = [
    ("fields", STRICT,
     b"GET /index.html HTTP/1.1\r\nHost: x\r\nX-1: a\r\nX-2: b\r\nX-3: c\r\n"
     b"X-4: d\r\nX-5: e\r\nConnection: close\r\n\r\n",
     (400, None)),
    ("nul", STRICT,
     b"GET /index.html HTTP/1.1\r\nHost: x\r\nX-A: a\x00b\r\nConnection: close\r\n\r\n",
     (400, None)),
    ("fold", STRICT,
     b"GET /index.html HTTP/1.1\r\nHost: x\r\nX-F: a\r\n  b\r\n\tc\r\n"
     b"Connection: close\r\n\r\n",
     (200, ("X-Echo-F", "a b c"))),
    ("lf-limit", UNSAFE,
     b"GET /index.html HTTP/1.1\nHost: x\nX-L: " + LONG + b"\nConnection: close\n\n",
     (200, ("X-Echo-L", LONG.decode()))),
    ("plain", STRICT,
     b"GET /index.html HTTP/1.1\r\nHost: x\r\nX-A: one\r\nConnection: close\r\n\r\n",
     (200, ("X-Echo-A", "one"))),
]


def start():
    os.makedirs(os.path.join(work, "docs"), exist_ok=True)
    with open(os.path.join(work, "docs", "index.html"), "w") as f:
        f.write("hello\n")
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(CONF.format(prefix=prefix, work=work, strict=STRICT, unsafe=UNSAFE))
    open(os.path.join(work, "error_log"), "w").close()
    p = subprocess.Popen([os.path.join(prefix, "bin", "httpd"), "-f",
                          os.path.join(work, "httpd.conf"), "-DFOREGROUND"])
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", STRICT), 0.2).close()
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


def request(port, parts, pause):
    """send the parts (a pause between them), return (status, headers) of the
    response, read until the server closes"""
    s = socket.create_connection(("127.0.0.1", port), 10)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    data = b""
    try:
        for i, part in enumerate(parts):
            if i:
                time.sleep(pause)
            s.sendall(part)
        while True:
            b = s.recv(65536)
            if not b:
                break
            data += b
    except OSError as e:
        return ("error " + type(e).__name__, {})
    finally:
        s.close()
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
    try:
        status = int(head[0].split()[1])
    except (IndexError, ValueError):
        return ("bad response %r" % data[:60], {})
    hdrs = {}
    for line in head[1:]:
        k, _, v = line.partition(":")
        hdrs[k.strip()] = v.strip()
    return (status, hdrs)


def result(res, want):
    status, hdrs = res
    if status != want[0]:
        return False, "status %s" % (status,)
    if want[1]:
        got = hdrs.get(want[1][0])
        if got != want[1][1]:
            return False, "%s %r (%d bytes)" % (want[1][0], (got or "")[:20],
                                                len(got or ""))
    return True, ""


p = start()
report = []
try:
    for name, port, head, want in CASES:
        ok1, why = result(request(port, [head], 0), want)
        bad = [] if ok1 else ["one write: " + why]
        for k in range(1, len(head)):
            ok, why = result(request(port, [head[:k], head[k:]], PAUSE), want)
            if not ok:
                bad.append("split at %d: %s" % (k, why))
        ok, why = result(request(port, [head[i:i + 1] for i in range(len(head))],
                                 BYTE_PAUSE), want)
        if not ok:
            bad.append("byte per write: " + why)
        report.append(not bad)
        print("%-9s %d bytes, %d splits + one write + byte per write: %s%s"
              % (name, len(head), len(head) - 1, "OK" if not bad else "FAIL",
                 "" if not bad else " (%d) %s" % (len(bad), "; ".join(bad[:4]))))
finally:
    stop(p)
crashes = sum(1 for line in open(os.path.join(work, "error_log"))
              if "exit signal" in line)
print("crashes: %d" % crashes)
sys.exit(0 if all(report) and not crashes else 1)
