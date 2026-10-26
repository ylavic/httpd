"""ProxyAsyncDelay benchmark: blocking (-1) vs async (0, 1ms, 10ms) against
backends answering in 0/1/10/100ms, 64 clients on 8 worker threads.

usage: python3 -I bench.py HTTPD_PREFIX WORKDIR [delays] [backend_ms]
env: CLIENTS (64), SECONDS (10), POOLMAX (the backend pool's max=, 256; below
CLIENTS for a pool-bound run where requests wait for a connection), STRACE=1
(the httpd child's syscalls per request with strace -c over the measured
window: strace slows it down, so only the per-request ratios are meaningful),
LOGLEVEL (warn), CONF_EXTRA (appended to the httpd.conf, e.g.
"KeepAliveTimeout 1")
"""

import os
import signal
import subprocess
import sys
import time

prefix, work = sys.argv[1], sys.argv[2]
here = os.path.dirname(os.path.abspath(__file__))
DELAYS = (sys.argv[3] if len(sys.argv) > 3 else "-1,0,1ms,10ms").split(",")
BACKEND_MS = (sys.argv[4] if len(sys.argv) > 4 else "0,1,10,100").split(",")
CLIENTS = int(os.environ.get("CLIENTS", "64"))
SECONDS = os.environ.get("SECONDS", "10")
POOLMAX = os.environ.get("POOLMAX", "256")
STRACE = os.environ.get("STRACE") == "1"
LOGLEVEL = os.environ.get("LOGLEVEL", "warn")
CONF_EXTRA = os.environ.get("CONF_EXTRA", "")
# Stop strace a second before the end, so that the connections closed at the
# end of a run (keepalive, tunnels) aren't counted
STRACE_SECONDS = str(max(1, int(SECONDS) - 1))
os.makedirs(work, exist_ok=True)
FRONT, BACK = 18500, 18501
TICK = os.sysconf("SC_CLK_TCK")

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{front}
PidFile "{work}/httpd.pid"
ErrorLog "{work}/error_log"
LogLevel {loglevel}
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
ServerName localhost
StartServers 1
ServerLimit 1
ThreadLimit 8
ThreadsPerChild 8
MaxRequestWorkers 8
MinSpareThreads 1
MaxSpareThreads 8
AsyncRequestWorkerFactor 16
KeepAlive On
MaxKeepAliveRequests 0
KeepAliveTimeout 30
<Location "/b">
    ProxyPass "http://127.0.0.1:{back}/" max={poolmax}
    ProxyAsyncDelay {delay}
</Location>
"""


def tree_cpu(pid):
    """utime+stime (seconds) of pid and its children"""
    pids = [str(pid)] + subprocess.run(["pgrep", "-P", str(pid)], capture_output=True,
                                       text=True).stdout.split()
    total = 0
    for p in pids:
        try:
            with open("/proc/%s/stat" % p) as f:
                fields = f.read().rsplit(")", 1)[1].split()
            total += int(fields[11]) + int(fields[12])
        except OSError:
            pass
    return total / TICK


def tree_ctxsw(pid):
    """context switches (voluntary + involuntary) of all the threads of pid and its
    children"""
    pids = [str(pid)] + subprocess.run(["pgrep", "-P", str(pid)], capture_output=True,
                                       text=True).stdout.split()
    total = 0
    for p in pids:
        try:
            tids = os.listdir("/proc/%s/task" % p)
        except OSError:
            continue
        for t in tids:
            try:
                with open("/proc/%s/task/%s/status" % (p, t)) as f:
                    for line in f:
                        if "ctxt_switches:" in line:
                            total += int(line.split()[1])
            except OSError:
                pass
    return total


def strace_per_req(n):
    """the main syscalls per request from strace -c's summary (strace.out), over
    its window (STRACE_SECONDS of the SECONDS measured, n requests in SECONDS)"""
    n = n * float(STRACE_SECONDS) / int(SECONDS)
    calls = {}
    with open(os.path.join(work, "strace.out")) as f:
        for line in f:
            fields = line.split()
            if len(fields) >= 5 and fields[0][0].isdigit() and fields[-1] != "total":
                calls[fields[-1]] = int(fields[3])
    total = sum(calls.values())
    top = sorted(calls.items(), key=lambda kv: -kv[1])[:10]
    return "total %.1f, " % (float(total) / n) + ", ".join(
        "%s %.2f" % (name, float(c) / n) for name, c in top)


def start_httpd(delay):
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(CONF.format(prefix=prefix, work=work, front=FRONT, back=BACK, delay=delay,
                            poolmax=POOLMAX, loglevel=LOGLEVEL) + CONF_EXTRA + "\n")
    open(os.path.join(work, "error_log"), "w").close()
    p = subprocess.Popen(["taskset", "-c", "0-3", os.path.join(prefix, "bin", "httpd"),
                          "-f", os.path.join(work, "httpd.conf"), "-DFOREGROUND"])
    for _ in range(100):
        r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                            "http://127.0.0.1:%d/b?d=0" % FRONT], capture_output=True, text=True)
        if r.stdout == "200":
            return p
        time.sleep(0.05)
    stop_httpd(p)
    raise SystemExit("httpd didn't start")


def stop_httpd(p):
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        for kid in subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True,
                                  text=True).stdout.split():
            os.kill(int(kid), signal.SIGKILL)
        p.kill()
        p.wait(10)


backend = subprocess.Popen(["taskset", "-c", "4,5", os.path.join(here, "backend"),
                            "-addr", "127.0.0.1:%d" % BACK])
time.sleep(0.5)
print("clients %d, %ss per run, 8 threads, pool max=%s; cpu = httpd tree CPU ms per 1000"
      " requests, cs = httpd context switches per request" % (CLIENTS, SECONDS, POOLMAX))
try:
    for delay in DELAYS:
        p = start_httpd(delay)
        try:
            for ms in BACKEND_MS:
                lg = subprocess.Popen(["taskset", "-c", "6,7", os.path.join(here, "loadgen"),
                                       "-url", "http://127.0.0.1:%d/b?d=%s" % (FRONT, ms),
                                       "-c", str(CLIENTS), "-d", SECONDS + "s", "-w", "2s"],
                                      stdout=subprocess.PIPE, text=True)
                time.sleep(2)
                st = None
                if STRACE:
                    child = subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True,
                                           text=True).stdout.split()[0]
                    st = subprocess.Popen(["timeout", "-s", "INT", STRACE_SECONDS, "strace", "-c",
                                           "-f", "-q", "-o", os.path.join(work, "strace.out"),
                                           "-p", child])
                c0, s0 = tree_cpu(p.pid), tree_ctxsw(p.pid)
                out = lg.communicate()[0].strip()
                c1, s1 = tree_cpu(p.pid), tree_ctxsw(p.pid)
                n = int(out.split(" n ")[1])
                cpu = (c1 - c0) * 1000.0 * 1000 / n if n else 0
                cs = float(s1 - s0) / n if n else 0
                print("delay %-5s backend %4sms: %s | cpu %.1f ms/1k req | cs %.1f/req"
                      % (delay, ms, out, cpu, cs), flush=True)
                if st:
                    st.wait()
                    print("    syscalls/req: " + strace_per_req(n), flush=True)
        finally:
            stop_httpd(p)
finally:
    backend.terminate()
    backend.wait(5)
