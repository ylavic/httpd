"""Check tunnels held by their forward hooks (ap_proxy_tunnel_hold())
through mod_aptest's "AptestTunnelHold" hook, on mod_proxy_http's Upgrade
tunnels to an echo backend (which may also send a tick every 100ms): many
tunnels holding each message on few threads, the other direction flowing
while one is held (and not, with "pause"), a hold longer than the idle
timeout (each direction on its own idle clock, the held one's stopped: the
other direction staying quiet ends the tunnel at the idle timeout, the
other one flowing keeps it until both are idle), the other direction's
clock restarted at the hold's start (the server quiet for longer than the
idle timeout, then a client's message held: echoed), a direction shut down
not ending the tunnel idle while the other one is held, a hold on a
service's socket timing out (the hook called again with APR_TIMEUP), a hold
without a timeout bounded by the idle timeout, holds delegated to a
subrequest per message (a proxied one suspending, the other direction
flowing meanwhile; one whose timeout is longer than the idle timeout
completing; one without a timeout bounded by the idle timeout: 504; a
static one ending at once), a graceful stop while held, a TLS front (two
messages decrypted at once, the second pending in mod_ssl while the first
is held), and two holds on sockets at once in both directions (no
EVENT_KEPT_MAX line: client, origin and two service sockets kept). "sync"
runs them with ProxyAsyncDelay -1 (a synchronous tunnel: every hold
refused, the hook doing its work blocking: the same bytes), "async" with
the holds in the MPM: the workers held (mod_status' BusyWorkers, but the
status request's own), the times and the other direction's flow are
checked there.

mod_aptest is built from ../../pyhttpd/mod_aptest with the install's apxs
into WORKDIR unless MOD_APTEST_SO is given; the Go backend (../backend) must
be built.

usage: MODES="sync async" python3 -I async-tunnel-hold-check.py HTTPD_PREFIX [MOD_APTEST_SO] WORKDIR
"""

import hashlib
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time

here = os.path.dirname(os.path.abspath(__file__))
if len(sys.argv) > 3:
    prefix, aptest, work = sys.argv[1], sys.argv[2], sys.argv[3]
else:
    prefix, aptest, work = sys.argv[1], None, sys.argv[2]
os.makedirs(work, exist_ok=True)
FRONT, ECHO, SERVICE, TLS, BACKEND = 18467, 18468, 18469, 18470, 18471
THREADS = 2
IDLE = 2

if not aptest:
    src = os.path.join(here, "..", "..", "pyhttpd", "mod_aptest", "mod_aptest.c")
    bdir = os.path.join(work, "aptest")
    os.makedirs(bdir, exist_ok=True)
    shutil.copy(src, bdir)
    r = subprocess.run([os.path.join(prefix, "bin", "apxs"), "-c", "mod_aptest.c"],
                       cwd=bdir, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("building mod_aptest failed:\n" + r.stdout + r.stderr)
    aptest = os.path.join(bdir, ".libs", "mod_aptest.so")

docs = os.path.join(work, "htdocs")
os.makedirs(docs, exist_ok=True)
with open(os.path.join(docs, "small.txt"), "wb") as f:
    f.write(b"small file\n")

cert, key = os.path.join(work, "cert.pem"), os.path.join(work, "key.pem")
if not os.path.exists(cert):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=127.0.0.1"],
                   check=True, capture_output=True)

backend = subprocess.Popen([os.path.join(here, "..", "backend"),
                            "-addr", "127.0.0.1:%d" % BACKEND])


def echo_conn(s):
    """The Upgrade's 101, then an echo; "tick" also sends "tick NNNN\\n"
    every 100ms (30 ticks); "quiet" doesn't echo what starts with "quiet"."""
    lock = threading.Lock()
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            b = s.recv(4096)
            if not b:
                return
            data += b
        head, rest = data.split(b"\r\n\r\n", 1)
        m = re.search(rb"GET /\w+/ws\?m=(\w+) ", head)
        mode = m.group(1).decode() if m else "echo"
        s.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                  b"Connection: Upgrade\r\n\r\n")
        if mode == "tick":
            def ticks():
                try:
                    for i in range(30):
                        time.sleep(0.1)
                        with lock:
                            s.sendall(b"tick %04d\n" % i)
                except OSError:
                    pass
            threading.Thread(target=ticks, daemon=True).start()
        if rest:
            with lock:
                s.sendall(rest)
        while True:
            b = s.recv(65536)
            if not b:
                return
            if mode == "quiet" and b.startswith(b"quiet"):
                continue
            with lock:
                s.sendall(b)
    except OSError:
        pass
    finally:
        try:
            s.close()
        except OSError:
            pass


def service_conn(s):
    """A line "<ms>" answered "ok" after that delay."""
    try:
        f = s.makefile("rb")
        for line in f:
            time.sleep(int(line.strip() or 0) / 1000)
            s.sendall(b"ok\n")
    except (OSError, ValueError):
        pass
    finally:
        s.close()


def listen(port, fn):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", port))
    ls.listen(128)

    def serve():
        while True:
            try:
                s, _ = ls.accept()
            except OSError:
                return
            threading.Thread(target=fn, args=(s,), daemon=True).start()
    threading.Thread(target=serve, daemon=True).start()


listen(ECHO, echo_conn)
listen(SERVICE, service_conn)

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{front}
Listen 127.0.0.1:{tls}
PidFile "{work}/httpd.pid"
ErrorLog "{work}/error_log"
LogLevel warn aptest:info mpm_event:trace4
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule status_module modules/mod_status.so
LoadModule ssl_module modules/mod_ssl.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule aptest_module {aptest}
ServerName localhost
DocumentRoot "{docs}"
StartServers 1
ServerLimit 1
ThreadLimit {threads}
ThreadsPerChild {threads}
MaxRequestWorkers {threads}
MinSpareThreads 1
MaxSpareThreads {threads}
AsyncAdmissionBacklogPerThread 64
Timeout 5
GracefulShutdownTimeout 8
AcceptFilter http none
AcceptFilter https none
ProxyAsyncDelay {delay}
ProxyAsyncIdleTimeout {idle}
<Location "/server-status">
    SetHandler server-status
</Location>
ProxyPass "/p/" "http://127.0.0.1:{backend}/"
<Location "/p/">
    # The subrequests' own wait for the backend, longer than their bounds
    ProxyAsyncIdleTimeout 8
</Location>
{locations}
<VirtualHost 127.0.0.1:{tls}>
    SSLEngine on
    SSLCertificateFile "{cert}"
    SSLCertificateKeyFile "{key}"
{tlslocations}
</VirtualHost>
"""

HOLDS = {
    "timer": "in timer 300",
    "flow": "in timer 1000",
    "pause": "in timer 1000 pause",
    "idle": "in timer 3000",
    "timeup": "in socket %d 1500 timeout 500" % SERVICE,
    "never": "in never",
    "subreq": "in subreq /p/?d=200 timeout 1000",
    "sublong": "in subreq /p/?d=2600 timeout 5000",
    "subnone": "in subreq /p/?d=4000",
    "quiet": "in timer 500 every 4",
    "over": "out timer 3000",
    "static": "in subreq /small.txt",
    "stop": "in timer 3000",
    "tls": "in timer 300",
    "two": "both socket %d 300" % SERVICE,
}


def location(name):
    return """<Location "/%s/ws">
    ProxyPass "http://127.0.0.1:%d/%s/ws" upgrade=websocket max=32 timeout=%d
    AptestTunnelHold %s
</Location>""" % (name, ECHO, name, IDLE, HOLDS[name])


def start(mode):
    conf = CONF.format(prefix=prefix, front=FRONT, tls=TLS, work=work, aptest=aptest,
                       docs=docs, threads=THREADS, idle=IDLE, backend=BACKEND,
                       cert=cert, key=key, delay=(-1 if mode == "sync" else 0),
                       locations="\n".join(location(n) for n in HOLDS if n != "tls"),
                       tlslocations=location("tls"))
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(conf)
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


def stop(p, sig=signal.SIGTERM):
    p.send_signal(sig)
    try:
        p.wait(15)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait(10)


def errlog():
    with open(os.path.join(work, "error_log")) as f:
        return f.read()


def holds_log(name, lines):
    """The hook's report lines (aptest-thold) of the tunnels of a location,
    summed per direction, once that many lines are logged (the tunnels'
    requests ended, at most 5s)"""
    for _ in range(250):
        if len(re.findall(r"aptest-thold: /%s/ws " % name, errlog())) >= lines:
            break
        time.sleep(0.02)
    tot = {}
    for line in errlog().splitlines():
        m = re.search(r"aptest-thold: /(\w+)/ws (in|out): chunks=(\d+) holds=(\d+) "
                      r"async=(\d+) inline=(\d+) refused=(\d+) ready=(\d+) "
                      r"timeups=(\d+) enotimpl=(\d+) statuses=(\S*)", line)
        if not m or m.group(1) != name:
            continue
        d = tot.setdefault(m.group(2), {"chunks": 0, "holds": 0, "async": 0, "inline": 0,
                                        "refused": 0, "ready": 0, "timeups": 0,
                                        "enotimpl": 0, "statuses": []})
        for i, k in enumerate(("chunks", "holds", "async", "inline", "refused", "ready",
                               "timeups", "enotimpl")):
            d[k] += int(m.group(i + 3))
        d["statuses"] += [x for x in m.group(11).split(",") if x]
    return tot


def busy_workers():
    try:
        s = socket.create_connection(("127.0.0.1", FRONT), 5)
        s.settimeout(5)
        s.sendall(b"GET /server-status?auto HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        data = b""
        while True:
            b = s.recv(65536)
            if not b:
                break
            data += b
        s.close()
    except OSError:
        return None
    m = re.search(rb"BusyWorkers: (\d+)", data)
    return int(m.group(1)) if m else None


class Sampler:
    """BusyWorkers at the given times (s) from now, in the background, the
    status request's own excluded"""

    def __init__(self, times):
        self.samples = []
        self.t0 = time.monotonic()
        self.t = threading.Thread(target=self.run, args=(times,))
        self.t.start()

    def run(self, times):
        for when in times:
            time.sleep(max(0, when - (time.monotonic() - self.t0)))
            busy = busy_workers()
            self.samples.append(None if busy is None else busy - 1)

    def held(self):
        self.t.join()
        vals = [v for v in self.samples if v is not None]
        return max(vals) if vals else None


def read_head(s):
    data = b""
    while b"\r\n\r\n" not in data:
        b = s.recv(4096)
        if not b:
            break
        data += b
    return data.split(b"\r\n\r\n", 1) if b"\r\n\r\n" in data else (data, b"")


def shut(s):
    """Close a client's socket, its Reader thread blocked in recv() (a plain
    close() would send no FIN until that recv() returns)"""
    try:
        s.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    s.close()


def upgrade(name, mode="echo", tls=False):
    s = socket.create_connection(("127.0.0.1", TLS if tls else FRONT), 10)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s)
    s.settimeout(20)
    s.sendall(b"GET /%s/ws?m=%s HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
              b"Connection: Upgrade\r\n\r\n" % (name.encode(), mode.encode()))
    head, rest = read_head(s)
    return s, head.startswith(b"HTTP/1.1 101"), rest


class Reader:
    """What a tunnel's client receives, timed, in the background"""

    def __init__(self, s, rest=b""):
        self.s, self.t0 = s, time.monotonic()
        self.chunks = [(0.0, rest)] if rest else []
        self.closed = None
        self.th = threading.Thread(target=self.run, daemon=True)
        self.th.start()

    def run(self):
        while True:
            try:
                b = self.s.recv(65536)
            except OSError:
                b = b""
            if not b:
                self.closed = time.monotonic() - self.t0
                return
            self.chunks.append((time.monotonic() - self.t0, b))

    def data(self):
        return b"".join(c for _, c in self.chunks)

    def lines(self):
        """(time, line) of the complete lines received"""
        out, buf = [], b""
        for t, c in self.chunks:
            buf += c
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                out.append((t, line))
        return out

    def wait_for(self, pred, limit):
        t0 = time.monotonic()
        while time.monotonic() - t0 < limit:
            if pred(self):
                return True
            if self.closed is not None:
                return pred(self)
            time.sleep(0.02)
        return pred(self)


def echoes(rd):
    return [(t, l) for t, l in rd.lines() if not l.startswith(b"tick ")]


def ticks_between(rd, a, b):
    return sum(1 for t, l in rd.lines() if l.startswith(b"tick ") and a <= t < b)


report = []
results = {}  # (mode, case) -> bytes digest, for sync/async comparison


def check(mode, name, ok, detail):
    report.append(ok)
    print("%-6s %-58s %s  %s" % (mode, name, "OK  " if ok else "FAIL", detail))
    sys.stdout.flush()


def messages_case(name, n_tunnels, n_msgs, gap=0.0, limit=20):
    """n tunnels each sending n_msgs messages one after the other's echo:
    the echoes' digest, the time taken, the workers held meanwhile"""
    out = [None] * n_tunnels

    def one(i):
        s, ok, rest = upgrade(name)
        rd = Reader(s, rest)
        sent = b""
        for k in range(n_msgs):
            msg = b"%s %d message %d\n" % (name.encode(), i, k)
            sent += msg
            s.sendall(msg)
            rd.wait_for(lambda r: r.data().endswith(msg), limit)
            time.sleep(gap)
        shut(s)
        out[i] = (ok, rd.data() == sent, rd.data())
    t0 = time.monotonic()
    ths = [threading.Thread(target=one, args=(i,)) for i in range(n_tunnels)]
    for t in ths:
        t.start()
    return out, ths, t0


def join(ths, t0):
    for t in ths:
        t.join()
    return time.monotonic() - t0


modes = os.environ.get("MODES", "sync async").split()
try:
    for mode in modes:
        p = start(mode)
        stopped = False
        try:
            # 8 tunnels on 2 threads, 3 messages each held 300ms
            sampler = Sampler([0.15, 0.45, 0.75]) if mode == "async" else None
            out, ths, t0 = messages_case("timer", 8, 3)
            took = join(ths, t0)
            held = sampler.held() if sampler else None
            ok = all(o and o[0] and o[1] for o in out)
            results[(mode, "timer")] = hashlib.md5(b"".join(o[2] for o in out)).hexdigest()
            st = holds_log("timer", 8).get("in", {})
            if mode == "async":
                ok = ok and held == 0 and took < 2.5 and st.get("holds") == 24
            else:
                ok = ok and st.get("refused") == 24
            check(mode, "8 tunnels x 3 messages held 300ms, 2 threads", ok,
                  "%.2fs, echoed: %s, workers held %s, holds %s refused %s"
                  % (took, all(o and o[1] for o in out), held, st.get("holds"),
                     st.get("refused")))

            # The other direction flowing while one is held 1s (ticks), and
            # not with "pause"
            for name in ("flow", "pause"):
                s, ok, rest = upgrade(name, "tick")
                rd = Reader(s, rest)
                rd.wait_for(lambda r: any(l.startswith(b"tick ") for _, l in r.lines()), 2)
                t_sent = time.monotonic() - rd.t0
                s.sendall(b"%s message\n" % name.encode())
                rd.wait_for(lambda r: echoes(r), 3)
                e = echoes(rd)
                t_echo = e[0][0] - t_sent if e else None
                during = ticks_between(rd, t_sent + 0.15, t_sent + 0.85)
                shut(s)
                ok = ok and e and e[0][1] == b"%s message" % name.encode()
                if mode == "async":
                    ok = ok and 0.9 < t_echo < 1.6
                    ok = ok and (during >= 5 if name == "flow" else during == 0)
                check(mode, "%s: ticks while the client's message is held 1s%s"
                      % (name, " (paused)" if name == "pause" else ""), bool(ok),
                      "echo after %s, ticks during the hold %d"
                      % ("%.2fs" % t_echo if t_echo is not None else "-", during))

            # A hold (3s) longer than the idle timeout (2s), the other
            # direction quiet: its own idle clock ends the tunnel at the idle
            # timeout, the hold not over (sync: the hook sleeping, echoed,
            # then closed idle)
            s, ok, rest = upgrade("idle")
            rd = Reader(s, rest)
            s.sendall(b"idle message\n")
            rd.wait_for(lambda r: r.closed is not None, 10)
            e = echoes(rd)
            t_echo = e[0][0] if e else None
            shut(s)
            if mode == "async":
                ok = ok and not e and rd.closed is not None \
                    and IDLE - 0.3 < rd.closed < IDLE + 1
            else:
                ok = ok and e and e[0][1] == b"idle message" and rd.closed is not None
            check(mode, "a 3s hold, idle timeout 2s, the other direction quiet", bool(ok),
                  "echo at %s, closed at %s" % ("%.2fs" % t_echo if t_echo else "-",
                                                "%.2fs" % rd.closed if rd.closed else "-"))

            # The same hold, the other direction flowing (ticks for 3s): no
            # idle end while it flows, echoed at the hold's end, then closed
            # once both directions are idle for the idle timeout
            s, ok, rest = upgrade("idle", "tick")
            rd = Reader(s, rest)
            s.sendall(b"idle message\n")
            rd.wait_for(lambda r: r.closed is not None, 10)
            e = echoes(rd)
            t_echo = e[0][0] if e else None
            ticks = [t for t, l in rd.lines() if l.startswith(b"tick ")]
            last = max([t_echo or 0] + ticks)
            shut(s)
            ok = ok and e and e[0][1] == b"idle message" and rd.closed is not None
            if mode == "async":
                ok = ok and 2.8 < t_echo < 3.6 and len(ticks) >= 25 \
                    and IDLE - 0.5 < rd.closed - last < IDLE + 1
            check(mode, "a 3s hold, idle timeout 2s, the other direction flowing", bool(ok),
                  "echo at %s, %d ticks, the last activity at %.2fs, closed at %s"
                  % ("%.2fs" % t_echo if t_echo else "-", len(ticks), last,
                     "%.2fs" % rd.closed if rd.closed else "-"))

            # The server quiet for longer than the idle timeout while the
            # client talks (not echoed), then a client's message held 500ms:
            # the server's direction's clock restarts at the hold's start,
            # the message echoed rather than the tunnel ended then
            s, ok, rest = upgrade("quiet", "quiet")
            rd = Reader(s, rest)
            s.sendall(b"quiet hello\n")  # held, not echoed
            for k in range(3):
                time.sleep(0.8)
                s.sendall(b"quiet %d\n" % k)
            time.sleep(0.6)
            t_sent = time.monotonic() - rd.t0
            s.sendall(b"after-quiet message\n")
            rd.wait_for(lambda r: echoes(r), 3)
            e = echoes(rd)
            t_echo = e[0][0] - t_sent if e else None
            closed = rd.closed
            shut(s)
            ok = ok and e and e[0][1] == b"after-quiet message" and closed is None
            if mode == "async":
                ok = ok and 0.4 < t_echo < 1.0
            check(mode, "the server quiet past the idle timeout, then a hold", bool(ok),
                  "server quiet %.2fs, echo after %s, closed at %s"
                  % (t_sent, "%.2fs" % t_echo if t_echo is not None else "-",
                     "%.2fs" % closed if closed is not None else "-"))

            # The client's direction shut down (its message sent), the
            # server's echo held 3s, past the idle timeout (2s): the
            # direction over doesn't end the tunnel idle, the echo forwarded
            # at the hold's end, then the tunnel over
            s, ok, rest = upgrade("over")
            rd = Reader(s, rest)
            s.sendall(b"over message\n")
            s.shutdown(socket.SHUT_WR)
            rd.wait_for(lambda r: r.closed is not None, 8)
            e = echoes(rd)
            t_echo = e[0][0] if e else None
            shut(s)
            ok = ok and e and e[0][1] == b"over message" and rd.closed is not None
            if mode == "async":
                ok = ok and 2.8 < t_echo < 3.6
            check(mode, "a direction shut down, the other held 3s (idle 2s)", bool(ok),
                  "echo at %s, closed at %s"
                  % ("%.2fs" % t_echo if t_echo else "-",
                     "%.2fs" % rd.closed if rd.closed else "-"))

            # A hold on a service answering after 1.5s with a 500ms timeout:
            # the hook called again with APR_TIMEUP (it forwards anyway)
            s, ok, rest = upgrade("timeup")
            rd = Reader(s, rest)
            s.sendall(b"timeup message\n")
            rd.wait_for(lambda r: echoes(r), 5)
            e = echoes(rd)
            shut(s)
            st = holds_log("timeup", 1).get("in", {})
            ok = ok and e and e[0][1] == b"timeup message"
            if mode == "async":
                ok = ok and 0.4 < e[0][0] < 1.2 and st.get("timeups") == 1
            check(mode, "a hold's timeout (500ms, service 1.5s): APR_TIMEUP", bool(ok),
                  "echo at %s, timeups %s" % ("%.2fs" % e[0][0] if e else "-",
                                              st.get("timeups")))

            # A hold without a timeout (a notifier never notified): bounded
            # by the idle timeout, the hook called again with APR_TIMEUP (the
            # other direction flowing, so it doesn't end the tunnel first)
            s, ok, rest = upgrade("never", "tick")
            rd = Reader(s, rest)
            s.sendall(b"never message\n")
            rd.wait_for(lambda r: echoes(r), 6)
            e = echoes(rd)
            shut(s)
            st = holds_log("never", 1).get("in", {})
            ok = ok and e and e[0][1] == b"never message"
            if mode == "async":
                ok = ok and IDLE - 0.3 < e[0][0] < IDLE + 1 and st.get("timeups") == 1
            check(mode, "a hold without timeout: bounded by the idle timeout", bool(ok),
                  "echo at %s, timeups %s" % ("%.2fs" % e[0][0] if e else "-",
                                              st.get("timeups")))

            # A proxied subrequest (200ms) per message, delegated, the ticks
            # flowing meanwhile; 8 tunnels on 2 threads
            sampler = Sampler([0.1, 0.3, 0.5]) if mode == "async" else None
            res = [None] * 8

            def sub(i):
                s, ok, rest = upgrade("subreq", "tick")
                rd = Reader(s, rest)
                time.sleep(0.05)
                t_sent = time.monotonic() - rd.t0
                s.sendall(b"subreq %d message\n" % i)
                rd.wait_for(lambda r: echoes(r), 5)
                e = echoes(rd)
                during = ticks_between(rd, t_sent + 0.05, t_sent + 0.2)
                shut(s)
                res[i] = (ok and bool(e) and e[0][1] == b"subreq %d message" % i,
                          e[0][0] - t_sent if e else None, during)
            t0 = time.monotonic()
            ths = [threading.Thread(target=sub, args=(i,)) for i in range(8)]
            for t in ths:
                t.start()
            took = join(ths, t0)
            held = sampler.held() if sampler else None
            st = holds_log("subreq", 8).get("in", {})
            ok = all(r and r[0] for r in res)
            flowing = sum(1 for r in res if r and r[2] >= 1)
            if mode == "async":
                ok = ok and held == 0 and st.get("async") == 8 and flowing >= 6 \
                    and all(r[1] is not None and r[1] > 0.18 for r in res) \
                    and st.get("statuses") == ["200"] * 8
            else:
                ok = ok and st.get("refused") == 8 and st.get("statuses") == ["200"] * 8
            check(mode, "8 tunnels, a delegated subrequest (200ms) per message", ok,
                  "%.2fs, workers held %s, async %s refused %s, statuses %s, "
                  "ticks flowing in %d" % (took, held, st.get("async"), st.get("refused"),
                                           ",".join(st.get("statuses", [])), flowing))

            # A delegated subrequest (2.6s) whose timeout (5s) is longer
            # than the idle timeout, the other direction flowing (ticks):
            # it completes, echoed after it, the tunnel not ended before
            s, ok, rest = upgrade("sublong", "tick")
            rd = Reader(s, rest)
            s.sendall(b"sublong message\n")
            rd.wait_for(lambda r: echoes(r), 6)
            e = echoes(rd)
            t_echo = e[0][0] if e else None
            closed = rd.closed
            shut(s)
            st = holds_log("sublong", 1).get("in", {})
            ok = ok and e and e[0][1] == b"sublong message" \
                and (closed is None or closed > t_echo) and st.get("statuses") == ["200"]
            if mode == "async":
                ok = ok and 2.5 < t_echo < 3.5 and st.get("async") == 1
            check(mode, "a delegated subrequest (2.6s, timeout 5s), idle 2s", bool(ok),
                  "echo at %s, closed at %s, statuses %s"
                  % ("%.2fs" % t_echo if t_echo else "-",
                     "%.2fs" % closed if closed is not None else "-",
                     ",".join(st.get("statuses", []))))

            # A delegated subrequest (4s) without a timeout: bounded by the
            # idle timeout (the holder's), its done getting 504, then
            # echoed (sync: run blocking, 200)
            s, ok, rest = upgrade("subnone", "tick")
            rd = Reader(s, rest)
            s.sendall(b"subnone message\n")
            rd.wait_for(lambda r: echoes(r), 7)
            e = echoes(rd)
            t_echo = e[0][0] if e else None
            shut(s)
            st = holds_log("subnone", 1).get("in", {})
            ok = ok and e and e[0][1] == b"subnone message"
            if mode == "async":
                ok = ok and IDLE - 0.3 < t_echo < IDLE + 1 and st.get("statuses") == ["504"]
            else:
                ok = ok and st.get("statuses") == ["200"]
            check(mode, "a delegated subrequest without timeout: the idle timeout",
                  bool(ok), "echo at %s, statuses %s"
                  % ("%.2fs" % t_echo if t_echo else "-",
                     ",".join(st.get("statuses", []))))

            # A static subrequest per message: ended at once, the hold
            # undone
            out, ths, t0 = messages_case("static", 1, 3)
            took = join(ths, t0)
            st = holds_log("static", 1).get("in", {})
            ok = all(o and o[0] and o[1] for o in out) and st.get("statuses") == ["200"] * 3
            if mode == "async":
                ok = ok and st.get("inline") == 3 and st.get("holds") == 0
            check(mode, "a static subrequest per message: ended at once", ok,
                  "%.2fs, inline %s refused %s statuses %s"
                  % (took, st.get("inline"), st.get("refused"),
                     ",".join(st.get("statuses", []))))

            # TLS front: two messages decrypted at once, the second pending
            # in mod_ssl while the first is held (300ms each)
            s, ok, rest = upgrade("tls", tls=True)
            rd = Reader(s, rest)
            msgs = b"tls message 1\n" + b"tls message 2\n"
            s.sendall(b"tls message 1\n")
            s.sendall(b"tls message 2\n")
            rd.wait_for(lambda r: r.data().endswith(msgs), 4)
            got = rd.data()
            t_last = rd.chunks[-1][0] if rd.chunks else None
            shut(s)
            ok = ok and got == msgs
            if mode == "async":
                ok = ok and t_last is not None and t_last < 1.5
            check(mode, "TLS front: the 2nd message pending while the 1st held", bool(ok),
                  "%r at %s" % (got, "%.2fs" % t_last if t_last else "-"))

            # Holds on sockets at once in both directions (the ticks held
            # too, 3 messages): from their second holds the client, the
            # origin and both sockets are kept, no EVENT_KEPT_MAX line
            before = errlog().count("EVENT_KEPT_MAX")
            s, ok, rest = upgrade("two", "tick")
            rd = Reader(s, rest)
            time.sleep(0.3)
            for k in range(3):
                msg = b"two message %d" % k
                s.sendall(msg + b"\n")
                rd.wait_for(lambda r: any(l == msg for _, l in echoes(r)), 4)
            e = echoes(rd)
            shut(s)
            st = holds_log("two", 2)
            kept = errlog().count("EVENT_KEPT_MAX") - before
            ok = ok and [l for _, l in e] == [b"two message %d" % k for k in range(3)]
            if mode == "async":
                ok = ok and kept == 0 and st.get("in", {}).get("holds", 0) == 3 \
                    and st.get("out", {}).get("holds", 0) >= 2
            check(mode, "holds on sockets in both directions: no EVENT_KEPT_MAX", bool(ok),
                  "in holds %s, out holds %s, EVENT_KEPT_MAX lines %d"
                  % (st.get("in", {}).get("holds"), st.get("out", {}).get("holds"), kept))

            # A graceful stop while 4 tunnels are held (3s, the other
            # direction flowing): the holds complete, echoed, then httpd
            # stops (2 synchronous tunnels, the threads)
            rds = []
            n = 4 if mode == "async" else THREADS
            for i in range(n):
                s, ok, rest = upgrade("stop", "tick")
                rd = Reader(s, rest)
                s.sendall(b"stop %d message\n" % i)
                rds.append((s, ok, rd))
            time.sleep(0.5)
            t0 = time.monotonic()
            p.send_signal(signal.SIGWINCH)
            for s, ok, rd in rds:
                rd.wait_for(lambda r: echoes(r), 6)
                shut(s)
            try:
                p.wait(15)
                stopped = True
            except subprocess.TimeoutExpired:
                pass
            took = time.monotonic() - t0
            echoed = sum(1 for _, ok, rd in rds if ok and echoes(rd)
                         and echoes(rd)[0][1].startswith(b"stop "))
            ok = stopped and echoed == n
            check(mode, "graceful stop while %d tunnels are held 3s" % n, ok,
                  "echoed %d, stopped %s after %.1fs" % (echoed, stopped, took))

            log = errlog()
            check(mode, "error_log: no crash, no unexpected error",
                  log.count("exit signal") + log.count("AH00052") == 0
                  and "tunnel forward hook held" not in log
                  and "AH10295" not in log, "")
        finally:
            if not stopped:
                stop(p)
    if "sync" in modes and "async" in modes:
        check("both", "same bytes sync and async (8 tunnels x 3 messages)",
              results.get(("sync", "timer")) == results.get(("async", "timer")), "")
finally:
    backend.terminate()
    backend.wait()

sys.exit(0 if all(report) else 1)
