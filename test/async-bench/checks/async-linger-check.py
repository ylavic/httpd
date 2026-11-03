"""Check the lingering close's bounds and the closes of the connections whose
response timed out:
- a client not reading a Connection: close response (Timeout 2): its output
  times out in write completion then in the shutdown queue, a worker closes
  it (aborted): the access log has the request's line, the scoreboard no
  worker left logging ("L") nor busy;
- a client trickling bytes after an early error (413, LimitRequestBody):
  closed at the lingering close's total bound (30s), and at its short one
  (2s) after a request head timeout (mod_reqtimeout's
  "short-lingering-close" note, RequestReadTimeout header=1);
- clients sending as fast as they can after an early error don't hold the
  workers: requests on other connections are served meanwhile.

usage: python3 -I async-linger-check.py HTTPD_PREFIX WORKDIR
"""

import os
import re
import socket
import threading
import time

here = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(here, "async-proto-check.py")).read().split("report = []")[0])

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{front}
PidFile "{work}/httpd.pid"
ErrorLog "{work}/error_log"
LogLevel warn
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule status_module modules/mod_status.so
LoadModule reqtimeout_module modules/mod_reqtimeout.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
ServerName localhost
StartServers 1
ServerLimit 1
ThreadLimit 2
ThreadsPerChild 2
MaxRequestWorkers 2
MinSpareThreads 1
MaxSpareThreads 2
Timeout 2
KeepAliveTimeout 5
RequestReadTimeout handshake=0 header=1 body=0
LogFormat "%r %>s" t
CustomLog "{work}/access_log" t
LimitRequestBody 10
<Location "/server-status">
    SetHandler server-status
</Location>
<Location "/slow">
    ProxyPass "http://127.0.0.1:{backend}/slow" {passopts}
    {asyncconf}
</Location>
"""


def big_GET(self):
    q = parse_qs(urlparse(self.path).query)
    if urlparse(self.path).path.endswith("/big"):
        size = int(q["size"][0])
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.end_headers()
        try:
            self.wfile.write(b"x" * size)
        except OSError:
            pass
    else:
        Slow.do_GET_orig(self)


Slow.do_GET_orig = Slow.do_GET
Slow.do_GET = big_GET


def status():
    st, body = get("/server-status?auto", timeout=5)
    out = {}
    for line in body.decode().splitlines():
        k, _, v = line.partition(": ")
        out[k] = v
    return out


def closed_after(s, t0, limit, payload, gap=0.5):
    """Wait for the server to close s for good (its FIN after the response
    is the lingering close's shutdown, the final close then resets what is
    sent), sending payload every gap seconds; the seconds since t0, or None
    after limit"""
    s.settimeout(gap)
    while time.monotonic() - t0 < limit:
        try:
            s.sendall(payload)
            s.recv(65536)
        except socket.timeout:
            continue
        except OSError:
            return round(time.monotonic() - t0, 1)
        time.sleep(gap)
    return None


report = []
p = start("ProxyAsyncDelay 0\n    ProxyAsyncIdleTimeout 10")
try:
    # 1. A response not read: closed by a worker, logged, scoreboard right
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    s.connect(("127.0.0.1", FRONT))
    s.sendall(b"GET /slow/big?d=0&size=8000000 HTTP/1.1\r\nHost: x\r\n"
              b"Connection: close\r\n\r\n")
    t0 = time.monotonic()
    when = None
    # Not read: wait for the request's access log line (its close), up to 15s
    while time.monotonic() - t0 < 15:
        time.sleep(0.5)
        with open(os.path.join(work, "access_log")) as f:
            if "/slow/big" in f.read():
                when = round(time.monotonic() - t0, 1)
                break
    s.close()
    time.sleep(0.5)
    st = status()
    sb = st.get("Scoreboard", "")
    report.append(("unread response: access log line", when is not None and when <= 10,
                   "after %ss (Timeout 2, write completion then shutdown)" % when))
    report.append(("unread response: scoreboard", "L" not in sb
                   and int(st.get("BusyWorkers", "9")) <= 1,
                   "Scoreboard %r BusyWorkers %s" % (sb, st.get("BusyWorkers"))))

    # 2. Trickling after an early error: the total bound (30s)
    s = socket.create_connection(("127.0.0.1", FRONT), timeout=5)
    s.sendall(b"POST /nothing HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\n\r\n")
    t0 = time.monotonic()
    head = s.recv(4096)
    ok413 = head.startswith(b"HTTP/1.1 413")
    when = closed_after(s, t0, 40, payload=b"x", gap=1)
    s.close()
    report.append(("trickling after a 413: total bound", ok413 and when is not None
                   and 28 <= when <= 35, "413 %s, closed after %ss (30s)" % (ok413, when)))

    # 3. Trickling after a request head timeout: the short bound (2s)
    s = socket.create_connection(("127.0.0.1", FRONT), timeout=5)
    s.sendall(b"GET /nothing HTTP/1.1\r\nHost: x\r\n")
    t0 = time.monotonic()
    when = closed_after(s, t0, 15, payload=b"x", gap=0.5)
    s.close()
    report.append(("trickling after a 408 (header=1): short bound", when is not None
                   and when <= 5, "closed after %ss (1s + 2s)" % when))

    # 4. Fast senders after an early error don't hold the workers
    stop_flood = []
    flooded = [0, 0]

    def flood(i):
        s = socket.create_connection(("127.0.0.1", FRONT), timeout=5)
        s.sendall(b"POST /nothing HTTP/1.1\r\nHost: x\r\nContent-Length: 100000000\r\n\r\n")
        block = b"y" * 65536
        s.settimeout(1)
        while not stop_flood:
            try:
                s.sendall(block)
                flooded[i] += len(block)
            except OSError:
                break
        s.close()
    fl = [threading.Thread(target=flood, args=(i,)) for i in range(2)]
    for t in fl:
        t.start()
    time.sleep(0.5)
    lat = []
    for i in range(20):
        t1 = time.monotonic()
        try:
            st_, _ = get("/nothing?probe=%d" % i, timeout=5)
        except OSError:
            st_ = None
        lat.append((st_, time.monotonic() - t1))
        time.sleep(0.1)
    stop_flood.append(1)
    for t in fl:
        t.join(10)
    lat_ok = [l for st_, l in lat if st_ == 404]
    med = sorted(lat_ok)[len(lat_ok) // 2] if lat_ok else None
    report.append(("fast senders lingering: probes served", len(lat_ok) == 20
                   and med is not None and med < 0.2,
                   "%d/20 probes, median %.1fms, flooded %dKB"
                   % (len(lat_ok), (med or 0) * 1000, sum(flooded) // 1024)))
finally:
    result = stop(p)
with open(os.path.join(work, "error_log")) as f:
    crit = [l for l in f if re.search(r"\[(\w+:)?(crit|alert|emerg)\]|AH00052", l)]
report.append(("httpd stopped cleanly", result == "stopped" and not crit,
               "%s%s" % (result, (", " + crit[0].strip()) if crit else "")))

failed = 0
for name, ok, info in report:
    print("%-55s %s  %s" % (name, "ok" if ok else "FAIL", info))
    failed += not ok
print("RESULT: %s" % ("PASS" if not failed else "%d FAILED" % failed))
raise SystemExit(1 if failed else 0)
