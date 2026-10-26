"""Tunnel benchmark: N established tunnels (Upgrade: echo through
mod_proxy_http, async by default) each sending a small message every second;
httpd's CPU and context switches per message (and syscalls with STRACE=1).

usage: python3 -I tunnelbench.py HTTPD_PREFIX WORKDIR [tunnels,...]
env: SECONDS (10), INTERVAL (1s, per tunnel), SIZE (64), DELAY (ProxyAsyncDelay,
0; -1 for blocking tunnels: one thread each, so no more than ThreadsPerChild),
STRACE=1 (see bench.py)
"""

import os
import subprocess
import sys
import time

here = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(here, "bench.py")).read().split("\nbackend = subprocess.Popen")[0])

TUNNELS = (sys.argv[3] if len(sys.argv) > 3 else "100,1000,5000").split(",")
INTERVAL = os.environ.get("INTERVAL", "1s")
SIZE = os.environ.get("SIZE", "64")
DELAY = os.environ.get("DELAY", "0")

# Each tunnel takes 2 fds of the pollset (sized ThreadsPerChild times the factor)
CONF = CONF.replace("AsyncRequestWorkerFactor 16", "AsyncRequestWorkerFactor 4000")
CONF = CONF.replace('<Location "/b">', """<Location "/t">
    ProxyPass "http://127.0.0.1:{back}/t" upgrade=echo max=20000 timeout=30
    ProxyAsyncDelay {delay}
</Location>
<Location "/b">""")

backend = subprocess.Popen(["taskset", "-c", "4,5", os.path.join(here, "backend"),
                            "-addr", "127.0.0.1:%d" % BACK])
time.sleep(0.5)
print("%ss per run, 8 threads, a %s-byte message every %s per tunnel, ProxyAsyncDelay %s;"
      " cpu = httpd tree CPU ms per 1000 messages, cs = httpd context switches per message"
      % (SECONDS, SIZE, INTERVAL, DELAY))
try:
    p = start_httpd(DELAY)
    try:
        for n_tunnels in TUNNELS:
            tg = subprocess.Popen(["taskset", "-c", "6,7", os.path.join(here, "tunnelgen"),
                                   "-addr", "127.0.0.1:%d" % FRONT, "-c", n_tunnels,
                                   "-i", INTERVAL, "-s", SIZE, "-d", SECONDS + "s", "-w", "2s"],
                                  stdout=subprocess.PIPE, text=True)
            # The tunnels are established before the warm-up starts: wait for
            # them (the backend's established connections from httpd)
            t_end = time.monotonic() + 60
            while time.monotonic() < t_end:
                est = subprocess.run(["ss", "-Htn", "state", "established", "dport", "= :%d"
                                      % BACK], capture_output=True, text=True).stdout.count("\n")
                if est >= int(n_tunnels) or tg.poll() is not None:
                    break
                time.sleep(0.2)
            time.sleep(2)
            st = None
            if STRACE:
                child = subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True,
                                       text=True).stdout.split()[0]
                st = subprocess.Popen(["timeout", "-s", "INT", STRACE_SECONDS, "strace", "-c",
                                       "-f", "-q", "-o", os.path.join(work, "strace.out"),
                                       "-p", child])
            c0, s0 = tree_cpu(p.pid), tree_ctxsw(p.pid)
            out = tg.communicate()[0].strip()
            c1, s1 = tree_cpu(p.pid), tree_ctxsw(p.pid)
            n = int(out.split(" n ")[1])
            cpu = (c1 - c0) * 1000.0 * 1000 / n if n else 0
            cs = float(s1 - s0) / n if n else 0
            print("%s | cpu %.1f ms/1k msg | cs %.1f/msg" % (out, cpu, cs), flush=True)
            if st:
                st.wait()
                print("    syscalls/msg: " + strace_per_req(n), flush=True)
    finally:
        stop_httpd(p)
finally:
    backend.terminate()
    backend.wait(5)
