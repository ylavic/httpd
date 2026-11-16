"""Check that the core abandons a request whose waits the MPM refuses (a bug of
the core or the MPM, made here by mod_aptest's "AP-Test-Refuse-Wait" request
header, see "the refused waits"): ap_mpm_register_wait() failing, or the
re-arm of the request's notifier failing, in the request's first run (its
handler suspending) and in a run from a continuation (waiting again). The
connection is closed without a response, at once (no hang), the error is
logged, no child crashes, and the server serves the next requests. "sync"
runs the same requests with AsyncRequests Off: nothing waits in the MPM, so
nothing is refused and they're answered as usual.

mod_aptest is built from ../../pyhttpd/mod_aptest with the install's apxs
into WORKDIR unless MOD_APTEST_SO is given.

usage: MODES="sync async" python3 -I async-refuse-check.py HTTPD_PREFIX [MOD_APTEST_SO] WORKDIR
"""

import http.client
import os
import shutil
import signal
import socket
import subprocess
import sys
import time

here = os.path.dirname(os.path.abspath(__file__))
if len(sys.argv) > 3:
    prefix, aptest, work = sys.argv[1], sys.argv[2], sys.argv[3]
else:
    prefix, aptest, work = sys.argv[1], None, sys.argv[2]
os.makedirs(work, exist_ok=True)
PORT = 18472
THREADS = 4

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

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{port}
PidFile "{work}/httpd.pid"
ErrorLog "{work}/error_log"
LogLevel warn aptest:info
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule aptest_module {aptest}
ServerName localhost
StartServers 1
ServerLimit 1
ThreadLimit {threads}
ThreadsPerChild {threads}
MaxRequestWorkers {threads}
MinSpareThreads 1
MaxSpareThreads {threads}
Timeout 10
KeepAliveTimeout 5
GracefulShutdownTimeout 3
AcceptFilter http none
LogFormat "%r %>s %D" t
CustomLog "{work}/access_log" t
{modeconf}
<Location "/timer">
    SetHandler aptest-wait
    AptestWait timer 200
</Location>
<Location "/notifier">
    SetHandler aptest-wait
    AptestWait notifier
</Location>
"""
MODES = {"sync": "AsyncRequests Off", "async": ""}

# (name, path, header, the run refused, the ERR line expected)
CASES = [
    ("register-first", "/timer", "register 1", "first",
     "can't wait for the 1 pending wait(s) of the request asynchronously: "
     "abandoning the request"),
    ("register-continuation", "/notifier", "register 2", "continuation",
     "can't wait for the 1 pending wait(s) of the request asynchronously: "
     "abandoning the request"),
    ("rearm-first", "/notifier", "rearm 1", "first",
     "can't re-arm the request's notifier: abandoning the request"),
    ("rearm-continuation", "/notifier", "rearm 2", "continuation",
     "can't re-arm the request's notifier: abandoning the request"),
]
EXPECTED = {"/timer": b"waited 200 ms",
            "/notifier": b"notifier: busy=EBUSY wait1=ok stale=dropped "
                         b"prenotified=ok unrearmed=declined"}
SYNC_EXPECTED = {"/timer": b"waited 200 ms", "/notifier": b"notifier: declined"}


def start(modeconf):
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(CONF.format(prefix=prefix, work=work, port=PORT, aptest=aptest,
                            threads=THREADS, modeconf=modeconf))
    for name in ("error_log", "access_log"):
        open(os.path.join(work, name), "w").close()
    p = subprocess.Popen([os.path.join(prefix, "bin", "httpd"), "-f",
                          os.path.join(work, "httpd.conf"), "-DFOREGROUND"])
    for _ in range(100):
        try:
            c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=1)
            c.request("GET", "/nothing")
            c.getresponse().read()
            c.close()
            return p
        except OSError:
            time.sleep(0.05)
    stop(p)
    raise SystemExit("httpd didn't start")


def kill_tree(p):
    for kid in subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True,
                              text=True).stdout.split():
        os.kill(int(kid), signal.SIGKILL)
    os.kill(p.pid, signal.SIGKILL)
    p.wait(10)


def stop(p):
    if p.poll() is not None:
        return "stopped already"
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
        return "stopped"
    except subprocess.TimeoutExpired:
        kill_tree(p)
        return "STOP HUNG (killed)"


def raw(path, header=None, limit=8):
    """one request on its own connection: (what the server sent, how the
    connection ended: 'closed' or 'HUNG', seconds)"""
    s = socket.create_connection(("127.0.0.1", PORT), timeout=limit)
    req = "GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n" % path
    if header:
        req += "AP-Test-Refuse-Wait: %s\r\n" % header
    s.sendall((req + "\r\n").encode())
    data, how, t0 = b"", "closed", time.monotonic()
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            data += b
    except socket.timeout:
        how = "HUNG"
    except ConnectionResetError:
        how = "closed"
    s.close()
    return data, how, round(time.monotonic() - t0, 2)


def body_of(data):
    return data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""


def errlog():
    with open(os.path.join(work, "error_log")) as f:
        return f.read()


report = []
for mode in os.environ.get("MODES", "sync async").split():
    p = start(MODES[mode])
    try:
        for name, path, header, run, line in CASES:
            before = errlog().count(line)
            data, how, secs = raw(path, header)
            time.sleep(0.2)  # the log line written meanwhile
            logged = errlog().count(line) - before
            if mode == "async":
                ok = (data == b"" and how == "closed" and secs < 5 and logged == 1)
                what = "connection %s in %.2fs, %d bytes, ERR line %d" % (how, secs, len(data),
                                                                          logged)
            else:
                ok = (how == "closed" and data.startswith(b"HTTP/1.1 200")
                      and body_of(data).startswith(SYNC_EXPECTED[path]) and logged == 0)
                what = "%s, ERR line %d" % (data.split(b"\r\n", 1)[0].decode(), logged)
            report.append("%s: %s (%s %s, refused in the %s run): %s%s"
                          % (mode, name, path, header, run, what, "" if ok else " FAIL"))
            # the server serves after it
            data, how, secs = raw(path)
            want = EXPECTED[path] if mode == "async" else SYNC_EXPECTED[path]
            ok = data.startswith(b"HTTP/1.1 200") and body_of(data).startswith(want)
            report.append("%s: %s then %s without refusal: %s%s"
                          % (mode, name, path, body_of(data).strip().decode(errors="replace"),
                             "" if ok else " FAIL"))
        log = errlog()
        crashes = log.count("exit signal")
        report.append("%s: error_log: {'crashes': %d, 'abandoned by its continuation': %d}%s"
                      % (mode, crashes, log.count("abandoned by its continuation"),
                         "" if crashes == 0 else " FAIL"))
    finally:
        report.append("%s: %s" % (mode, stop(p)))
print("\n".join(report))
