"""Large-body benchmark: responses of a few MB streamed by the backend through
mod_proxy_http, read by clients slower than the backend (so that the proxy
alternates between the backend and the client), or as fast as possible, and
uploads of a few MB sent in paced chunks; blocking (-1) vs async (0).
httpd's CPU and context switches per MB (and syscalls per request with
STRACE=1).

usage: python3 -I bodybench.py HTTPD_PREFIX WORKDIR [delays] [scenarios]
scenarios: down-slow (default), down-fast, up (all three by default)
env: CLIENTS (16), SECONDS (10), SIZE (4194304 bytes), CHUNK (65536: the
backend's writes, the slow client's reads and the upload's writes), PAUSE (1ms:
between the slow client's reads and the upload's writes), POOLMAX, STRACE=1,
LOGLEVEL, CONF_EXTRA (see bench.py)
"""

import os
import re
import subprocess
import sys
import time

here = os.path.dirname(os.path.abspath(__file__))
# bench.py's prefix, workdir, delays (its backend_ms argument is unused here)
exec(open(os.path.join(here, "bench.py")).read().split("\nbackend = subprocess.Popen")[0])

CLIENTS = int(os.environ.get("CLIENTS", "16"))
SIZE = int(os.environ.get("SIZE", str(4 * 1024 * 1024)))
CHUNK = int(os.environ.get("CHUNK", "65536"))
PAUSE = os.environ.get("PAUSE", "1ms")
SCENARIOS = (sys.argv[4] if len(sys.argv) > 4 else "down-slow,down-fast,up").split(",")
if len(sys.argv) <= 3:
    DELAYS = ["-1", "0"]


def loadgen_args(scenario):
    """the load generator's URL and options for a scenario"""
    url = "http://127.0.0.1:%d/b" % FRONT
    if scenario == "up":
        return [url, "-upload", str(SIZE), "-wchunk", str(CHUNK), "-wdelay", PAUSE]
    url += "?s=%d&c=%d" % (SIZE, CHUNK)
    if scenario == "down-slow":
        return [url, "-rchunk", str(CHUNK), "-rdelay", PAUSE]
    if scenario == "down-fast":
        return [url, "-rchunk", str(CHUNK)]
    raise SystemExit("unknown scenario %s" % scenario)


backend = subprocess.Popen(pinned(BACKEND_CPUS, [os.path.join(here, "backend"),
                                                 "-addr", "127.0.0.1:%d" % BACK]))
time.sleep(0.5)
print("clients %d, %ss per run, 8 threads, pool max=%s, %d-byte bodies in %d-byte chunks,"
      " %s between the slow reads and the upload writes; cpu = httpd tree CPU ms per MB,"
      " cs = httpd context switches per MB" % (CLIENTS, SECONDS, POOLMAX, SIZE, CHUNK, PAUSE))
try:
    for delay in DELAYS:
        p = start_httpd(delay)
        try:
            for scenario in SCENARIOS:
                args = loadgen_args(scenario)
                url, opts = args[0], args[1:]
                lg = subprocess.Popen(pinned(TOOLS_CPUS, [os.path.join(here, "loadgen"),
                                       "-url", url, "-c", str(CLIENTS), "-d", SECONDS + "s",
                                       "-w", "2s"] + opts),
                                      stdout=subprocess.PIPE, text=True)
                time.sleep(2)
                st = None
                if STRACE:
                    child = subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True,
                                           text=True).stdout.split()[0]
                    st = tracer(child)
                c0, s0 = tree_cpu(p.pid), tree_ctxsw(p.pid)
                out = lg.communicate()[0].strip()
                c1, s1 = tree_cpu(p.pid), tree_ctxsw(p.pid)
                m = re.search(r" n (\d+) mbps ([\d.]+)", out)
                n, mb = (int(m.group(1)), float(m.group(2)) * int(SECONDS)) if m else (0, 0)
                cpu = (c1 - c0) * 1000.0 / mb if mb else 0
                cs = float(s1 - s0) / mb if mb else 0
                print("delay %-5s %-9s: %s | cpu %.1f ms/MB | cs %.1f/MB"
                      % (delay, scenario, out, cpu, cs), flush=True)
                if st:
                    st.wait()
                    print("    syscalls/req: " + strace_per_req(n), flush=True)
        finally:
            stop_httpd(p)
finally:
    backend.terminate()
    backend.wait(5)
