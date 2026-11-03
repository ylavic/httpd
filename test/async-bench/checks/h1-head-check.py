"""Check the HTTP/1 head rules on both sides (ap_h1_head_parse()): request
heads sent by a client (HttpProtocolOptions Strict and Unsafe, the
LimitRequest* limits), and response heads and trailers sent by a backend to
mod_proxy_http (ProxyHttpProtocolOptions Strict and Unsafe, the
ProxyLimitResponse* limits), each head sent whole, then one byte per packet,
then split in two at every offset (the reads resumed after EAGAIN).

usage: MODES="sync async" python3 -I h1-head-check.py HTTPD_PREFIX WORKDIR
  (the request heads are checked in the first mode only: their reading
  doesn't depend on ProxyAsyncDelay; SPLITS="whole byte every" by default)
"""

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
os.makedirs(os.path.join(work, "htdocs"), exist_ok=True)
RAW, FRONT, ECHO, FRONT_UNSAFE = 18431, 18432, 18433, 18434
MODES = os.environ.get("MODES", "sync async").split()
SPLITS = os.environ.get("SPLITS", "whole byte every").split()
GAP = 0.005  # between the packets of a split head

# The limits configured on both sides (the request line's and field's limit
# + 1 is accepted, as ap_fgetline() always did)
LIM_LINE, LIM_FIELD, LIM_FIELDS = 100, 100, 10

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{front}
Listen 127.0.0.1:{front_unsafe}
PidFile "{work}/httpd.pid"
ErrorLog "{work}/error_log"
LogLevel warn http:debug core:info
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
ServerName localhost
DocumentRoot "{work}/htdocs"
StartServers 1
ServerLimit 1
ThreadsPerChild 8
MaxRequestWorkers 8
KeepAliveTimeout 2
Timeout 10
LimitRequestLine {lim_line}
LimitRequestFieldSize {lim_field}
LimitRequestFields {lim_fields}
ProxyLimitResponseLine {lim_line}
ProxyLimitResponseFieldSize {lim_field}
ProxyLimitResponseFields {lim_fields}
{asyncconf}
ProxyPass "/echo" "http://127.0.0.1:{echo}/echo" disablereuse=on
ProxyPass "/b/" "http://127.0.0.1:{raw}/b/" disablereuse=on
ProxyPass "/u/" "http://127.0.0.1:{raw}/u/" disablereuse=on
<Location "/u/">
    ProxyHttpProtocolOptions Unsafe
</Location>
<VirtualHost 127.0.0.1:{front_unsafe}>
    HttpProtocolOptions Unsafe
</VirtualHost>
"""


# The echo backend: the request's headers in the body, "name: value" lines
class Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = "".join("%s: %s\n" % kv for kv in self.headers.items()).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


echo = ThreadingHTTPServer(("127.0.0.1", ECHO), Echo)
threading.Thread(target=echo.serve_forever, daemon=True).start()


def send_split(sock, data, split, head_len):
    """Send data whole, one byte per packet, or in two at the offset split"""
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if split == "whole":
        sock.sendall(data)
    elif split == "byte":
        for i in range(head_len):
            sock.sendall(data[i:i + 1])
            time.sleep(GAP / 4)
        sock.sendall(data[head_len:])
    else:
        sock.sendall(data[:split])
        time.sleep(GAP)
        sock.sendall(data[split:])


# The raw backend: answers /b/<n> and /u/<n> with RESPONSES[n], split as the
# "split" query says, then closes
RESPONSES = []
lock = threading.Lock()


def raw_serve(conn):
    try:
        conn.settimeout(10)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk
        m = re.match(rb"GET /[bu]/(\d+)\?split=(\w+)", data)
        resp, head_len = RESPONSES[int(m.group(1))]
        split = m.group(2).decode()
        send_split(conn, resp, split if split in ("whole", "byte") else int(split),
                   head_len)
        time.sleep(0.01)
    except OSError:
        pass
    finally:
        conn.close()


def raw_backend():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", RAW))
    s.listen(64)
    while True:
        c, _ = s.accept()
        threading.Thread(target=raw_serve, args=(c,), daemon=True).start()


threading.Thread(target=raw_backend, daemon=True).start()


def read_response(sock, timeout=5):
    """(status, fields, body, complete) of a response on sock, status None if
    nothing came, 0 if not an HTTP/1 response (an HTTP/0.9 one)"""
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            while b"\r\n\r\n" not in data:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
            # skip interim (1xx) responses
            if not re.match(rb"HTTP/1\.\d 1\d\d", data) or b"\r\n\r\n" not in data:
                break
            data = data.partition(b"\r\n\r\n")[2]
    except OSError:
        pass
    if not data:
        return None, {}, b"", False
    if not data.startswith(b"HTTP/1."):
        return 0, {}, data, True
    head, _, rest = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1])
    fields = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        fields.setdefault(k.strip().lower(), []).append(v.strip())
    complete = True
    try:
        if "content-length" in fields:
            n = int(fields["content-length"][0])
            while len(rest) < n:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                rest += chunk
            complete = len(rest) >= n
        elif fields.get("transfer-encoding") == ["chunked"]:
            while not re.search(rb"(^|\r\n)0\r\n(.*\r\n)?\r\n$", rest, re.S):
                chunk = sock.recv(65536)
                if not chunk:
                    complete = False
                    break
                rest += chunk
            if complete:
                body, trailers = b"", rest
                while True:
                    size, _, trailers = trailers.partition(b"\r\n")
                    n = int(size.split(b";")[0], 16)
                    if n == 0:
                        break
                    body += trailers[:n]
                    trailers = trailers[n + 2:]
                for line in trailers.decode("latin-1").split("\r\n"):
                    if ":" in line:
                        k, _, v = line.partition(":")
                        fields.setdefault(k.strip().lower(), []).append(v.strip())
                rest = body
    except OSError:
        complete = False
    return status, fields, rest, complete


def front_request(port, data, split, head_len, eof=False):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        send_split(s, data, split, head_len)
        if eof:
            s.shutdown(socket.SHUT_WR)
        return read_response(s)


def splits_of(head_len):
    out = []
    for sp in SPLITS:
        if sp == "every":
            out += list(range(1, head_len))
        else:
            out.append(sp)
    return out


def log_size():
    try:
        return os.path.getsize(os.path.join(work, "error_log"))
    except OSError:
        return 0


def new_log(pos):
    with open(os.path.join(work, "error_log"), "rb") as f:
        f.seek(pos)
        return f.read().decode("latin-1")


H = b"Host: localhost\r\n"


def req(line=b"GET /echo HTTP/1.1", fields=(H,), end=b"\r\n", pre=b""):
    return pre + line + b"\r\n" + b"".join(fields) + end


def fl(name, size):
    """A field line of size bytes, line end excluded"""
    return name + b": " + b"v" * (size - len(name) - 2) + b"\r\n"


# Request heads: (name, port, bytes, expected status (None: no response,
# 0: any response), expected echoed header or None, eof after sending)
REQUESTS = [
    ("plain", FRONT, req(fields=(H, b"X-A: a\r\n")), 200, "x-a: a", False),
    ("bare LF (Strict)", FRONT, b"GET /echo HTTP/1.1\nHost: localhost\n\n", 400, None, False),
    ("bare LF in a field (Strict)", FRONT, req(fields=(H, b"X-A: a\n")), 400, None, False),
    ("bare LF (Unsafe)", FRONT_UNSAFE, b"GET /echo HTTP/1.1\nHost: localhost\nX-A: a\n\n",
     200, "x-a: a", False),
    ("NUL in a value", FRONT, req(fields=(H, b"X-A: a\0b\r\n")), 400, None, False),
    ("NUL in a value (Unsafe)", FRONT_UNSAFE, req(fields=(H, b"X-A: a\0b\r\n")), 400, None,
     False),
    ("NUL in the request line", FRONT, req(line=b"GET /ec\0ho HTTP/1.1"), 400, None, False),
    ("obs-fold", FRONT, req(fields=(H, b"X-A: a  \r\n  b\r\n")), 200, "x-a: a b", False),
    ("obs-folds", FRONT, req(fields=(H, b"X-A: a\r\n b\r\n\t c\r\n")), 200, "x-a: a b c",
     False),
    ("obs-fold (Unsafe)", FRONT_UNSAFE, req(fields=(H, b"X-A: a\r\n b\r\n")), 200,
     "x-a: a b", False),
    ("blank continuation", FRONT, req(fields=(H, b"X-A: a\r\n  \r\n")), 400, None, False),
    ("continuation first", FRONT, req(fields=(b" X-A: a\r\n", H)), 400, None, False),
    ("no colon", FRONT, req(fields=(H, b"X-A\r\n")), 400, None, False),
    ("no colon (Unsafe)", FRONT_UNSAFE, req(fields=(H, b"X-A\r\n")), 400, None, False),
    ("space in a name", FRONT, req(fields=(H, b"X A: a\r\n")), 400, None, False),
    ("space in a name (Unsafe)", FRONT_UNSAFE, req(fields=(H, b"X A: a\r\n")), 400, None,
     False),
    ("empty name (Unsafe)", FRONT_UNSAFE, req(fields=(H, b": a\r\n")), 400, None, False),
    ("CTL in a value", FRONT, req(fields=(H, b"X-A: a\x01b\r\n")), 400, None, False),
    ("CTL in a value (Unsafe)", FRONT_UNSAFE, req(fields=(H, b"X-A: a\x01b\r\n")), 200,
     None, False),
    ("VT in a value (Unsafe)", FRONT_UNSAFE, req(fields=(H, b"X-A: a\x0bb\r\n")), 400, None,
     False),
    ("field at the limit + 1", FRONT, req(fields=(H, fl(b"X-A", LIM_FIELD + 1))), 200, None,
     False),
    ("field at the limit + 2", FRONT, req(fields=(H, fl(b"X-A", LIM_FIELD + 2))), 400, None,
     False),
    ("folded field within the limit joined", FRONT,
     req(fields=(H, b"X-A: " + b"a" * 45 + b"\r\n" + b" " * 20 + b"b" * 45 + b"\r\n")),
     200, "x-a: " + "a" * 45 + " " + "b" * 45, False),
    ("fields at the limit", FRONT,
     req(fields=[H] + [b"X-%d: a\r\n" % i for i in range(LIM_FIELDS - 1)]), 200, None, False),
    ("fields over the limit", FRONT,
     req(fields=[H] + [b"X-%d: a\r\n" % i for i in range(LIM_FIELDS)]), 400, None, False),
    ("request line at the limit + 1", FRONT,
     req(line=b"GET /echo?" + b"q" * (LIM_LINE + 1 - 19) + b" HTTP/1.1"), 200, None, False),
    ("request line at the limit + 2", FRONT,
     req(line=b"GET /echo?" + b"q" * (LIM_LINE + 2 - 19) + b" HTTP/1.1"), 414, None, False),
    ("10 empty lines first", FRONT, req(pre=b"\r\n" * 10), 200, None, False),
    ("11 empty lines first", FRONT, req(pre=b"\r\n" * 11), 400, None, False),
    ("HTTP/0.9 answered at once", FRONT, b"GET /\r\n", 0, None, False),
    ("closed in the request line", FRONT, b"GET /echo HT", None, None, True),
    ("closed in the fields", FRONT, b"GET /echo HTTP/1.1\r\n" + H, 400, None, True),
]


def resp(fields=(), status=b"HTTP/1.1 200 OK", end=b"\r\n", body=b"OK", pre=b"",
         cl=True):
    if not status.endswith(b"\n"):
        status += b"\r\n"
    head = (pre + status + b"".join(fields)
            + (b"Content-Length: %d\r\n" % len(body) if cl else b"") + end)
    return head + body, len(head)


def chunked(trailers):
    """A chunked response, split anywhere (its trailers included)"""
    data = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"2\r\nOK\r\n0\r\n" + trailers + b"\r\n")
    return data, len(data)


INTERIM = b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"

# Response heads: (name, response (bytes, length split), expected status with
# ProxyHttpProtocolOptions Strict and Unsafe, expected forwarded header or None)
# (an error in the trailers truncates the response, "trunc", or gives a 502
# if nothing was sent yet: BAD)
RESP_CASES = [
    ("plain", resp([b"X-A: a\r\n"]), 200, 200, "x-a: a"),
    ("bare LF", resp([b"X-A: a\n"], status=b"HTTP/1.1 200 OK\n", end=b"\n"), 502, 200,
     "x-a: a"),
    ("NUL in a value", resp([b"X-A: a\0b\r\n"]), 502, 502, None),
    ("obs-fold", resp([b"X-A: a \r\n  b\r\n"]), 200, 200, "x-a: a b"),
    ("obs-folds", resp([b"X-A: a\r\n b\r\n\tc\r\n"]), 200, 200, "x-a: a b c"),
    ("blank continuation", resp([b"X-A: a\r\n \r\n"]), 502, 502, None),
    ("continuation first", resp([b" X-A: a\r\n"]), 502, 502, None),
    ("no colon", resp([b"X-A\r\n"]), 502, 502, None),
    ("extra status line", resp([b"HTTP/1.1 200 OK\r\n"]), 502, 502, None),
    ("space in a name", resp([b"X A: a\r\n"]), 502, 502, None),
    ("empty name", resp([b": a\r\n"]), 502, 502, None),
    # accepted with Unsafe, then refused by the client side's output (Strict)
    ("CTL in a value", resp([b"X-A: a\x01b\r\n"]), 502, 500, None),
    ("field at the limit + 1", resp([fl(b"X-A", LIM_FIELD + 1)]), 200, 200, None),
    ("field at the limit + 2", resp([fl(b"X-A", LIM_FIELD + 2)]), 502, 502, None),
    ("fields at the limit", resp([b"X-%d: a\r\n" % i for i in range(LIM_FIELDS - 1)]),
     200, 200, None),
    ("fields over the limit", resp([b"X-%d: a\r\n" % i for i in range(LIM_FIELDS)]),
     502, 502, None),
    ("status line at the limit + 1",
     resp(status=b"HTTP/1.1 200 " + b"R" * (LIM_LINE + 1 - 13)), 200, 200, None),
    ("status line at the limit + 2",
     resp(status=b"HTTP/1.1 200 " + b"R" * (LIM_LINE + 2 - 13)), 502, 502, None),
    ("status line without reason", resp(status=b"HTTP/1.1 200"), 200, 200, None),
    ("CR in the status line", resp(status=b"HTTP/1.1 200\rX-B: b"), 502, 502, None),
    ("one stray CRLF", resp(pre=b"\r\n"), 200, 200, None),
    ("two stray CRLFs", resp(pre=b"\r\n\r\n"), 502, 502, None),
    ("HTTP/0.9", (b"hello\r\n", 7), 502, 502, None),
    ("interim", resp([b"X-A: a\r\n"], pre=INTERIM), 200, 200, "x-a: a"),
    ("9 interims", resp(pre=INTERIM * 9), 200, 200, None),
    ("10 interims", resp(pre=INTERIM * 10), 502, 502, None),
    ("closed in the fields", (b"HTTP/1.1 200 OK\r\nX-A: a\r\n", 25), 502, 502, None),
    ("trailers", chunked(b"X-T: t\r\n"), 200, 200, "x-t: t"),
    ("trailers folded", chunked(b"X-T: t\r\n u\r\n"), 200, 200, "x-t: t u"),
    ("bad trailer", chunked(b"X-T\r\n"), "BAD", "BAD", None),
    ("bare LF trailer", chunked(b"X-T: t\n"), "BAD", 200, "x-t: t"),
]
for _, r, _, _, _ in RESP_CASES:
    RESPONSES.append(r)


def start(asyncconf):
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(CONF.format(prefix=prefix, work=work, front=FRONT,
                            front_unsafe=FRONT_UNSAFE, echo=ECHO, raw=RAW,
                            lim_line=LIM_LINE, lim_field=LIM_FIELD,
                            lim_fields=LIM_FIELDS, asyncconf=asyncconf))
    open(os.path.join(work, "error_log"), "w").close()
    p = subprocess.Popen([os.path.join(prefix, "bin", "httpd"), "-f",
                          os.path.join(work, "httpd.conf"), "-DFOREGROUND"])
    for _ in range(100):
        try:
            if front_request(FRONT, req(), "whole", 0)[0] == 200:
                return p
        except OSError:
            pass
        time.sleep(0.05)
    stop(p)
    raise SystemExit("httpd didn't start")


def stop(p):
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
        return "stopped"
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait(10)
        return "STOP HUNG (killed)"


def outcome(r):
    status, fields, body, complete = r
    if status and not complete:
        return "trunc", fields
    return status, fields


report = []
failures = 0
for mi, mode in enumerate(MODES):
    p = start("ProxyAsyncDelay -1" if mode == "sync" else "")
    try:
        if mi == 0:
            for name, port, data, exp, field, eof in REQUESTS:
                bad = []
                for split in splits_of(len(data)):
                    pos = log_size()
                    status, fields, body, complete = front_request(port, data, split,
                                                                   len(data), eof)
                    ok = (status == exp or (exp == 0 and status is not None))
                    if ok and field and status == 200 and field.encode() not in body.lower():
                        ok = False
                    if ok and split == "whole" and exp == 400:
                        # the cause is logged (http:debug)
                        ok = "[http:debug]" in new_log(pos) or "[core:info]" in new_log(pos)
                    if not ok:
                        bad.append("%s: %s" % (split, status))
                failures += bool(bad)
                report.append("request %s: %s%s" % (
                    name, exp, (" FAIL " + ", ".join(bad[:5])
                                + (" (+%d)" % (len(bad) - 5) if len(bad) > 5 else ""))
                    if bad else " ok"))
        for idx, (name, (data, head_len), exp_strict, exp_unsafe, field) \
                in enumerate(RESP_CASES):
            for side, exp in (("b", exp_strict), ("u", exp_unsafe)):
                bad = []
                for split in splits_of(head_len):
                    pos = log_size()
                    path = b"/%s/%d?split=%s" % (side.encode(), idx, str(split).encode())
                    status, fields = outcome(front_request(
                        FRONT, req(line=b"GET " + path + b" HTTP/1.1"), "whole", 0))
                    ok = (status in ("trunc", 502)) if exp == "BAD" else (status == exp)
                    if ok and field and status == 200:
                        k, _, v = field.partition(": ")
                        ok = v in fields.get(k, [])
                    if ok and split == "whole" and exp != 200:
                        # the cause is logged (proxy_http at WARNING, or the
                        # proxy's error)
                        log = new_log(pos)
                        ok = any(m in log for m in ("[proxy_http:warn]", "[proxy:error]",
                                                    "[proxy_http:error]", "[http:error]"))
                    if not ok:
                        bad.append("%s: %s" % (split, status))
                failures += bool(bad)
                report.append("%s: response %s (%s): %s%s" % (
                    mode, name, "Strict" if side == "b" else "Unsafe", exp,
                    (" FAIL " + ", ".join(bad[:5])
                     + (" (+%d)" % (len(bad) - 5) if len(bad) > 5 else ""))
                    if bad else " ok"))
        crash = [l for l in new_log(0).splitlines()
                 if "exit signal" in l or "AH00052" in l]
        if crash:
            failures += 1
            report.append("%s: error_log: FAIL %s" % (mode, crash[0]))
    finally:
        report.append("%s: %s" % (mode, stop(p)))

report.append("h1-head: %s" % ("ok" if not failures else "%d FAIL" % failures))
print("\n".join(report))
