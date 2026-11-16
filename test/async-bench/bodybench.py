"""Large-body benchmark: responses of a few MB streamed by the backend through
mod_proxy_http, read by clients slower than the backend (so that the proxy
alternates between the backend and the client), or as fast as possible, and
uploads of a few MB sent in paced chunks; plus crawling clients, reading or
sending small chunks slowly through small socket buffers, so that a request
waits many times in the MPM; blocking (-1) vs async (0). httpd's CPU and
context switches per MB (and syscalls per request with STRACE=1).

usage: python3 -I bodybench.py HTTPD_PREFIX WORKDIR [delays] [scenarios]
scenarios: down-slow, down-fast, up, down-crawl, up-crawl (all by default)
env: CLIENTS (16), SECONDS (10), SIZE (4194304 bytes), CHUNK (65536: the
backend's writes, the slow client's reads and the upload's writes), PAUSE (1ms:
between the slow client's reads and the upload's writes), CRAWL_SIZE (1048576),
CRAWL_CHUNK (16384), CRAWL_PAUSE (20ms) for the crawl scenarios (which also run
with httpd's SendBufferSize and the client's receive buffer at CRAWL_CHUNK),
POOLMAX, STRACE=1, LOGLEVEL, CONF_EXTRA (see bench.py)
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
CRAWL_SIZE = int(os.environ.get("CRAWL_SIZE", str(1024 * 1024)))
CRAWL_CHUNK = int(os.environ.get("CRAWL_CHUNK", "16384"))
CRAWL_PAUSE = os.environ.get("CRAWL_PAUSE", "20ms")
SCENARIOS = (sys.argv[4] if len(sys.argv) > 4
             else "down-slow,down-fast,up,down-crawl,up-crawl").split(",")
if len(sys.argv) <= 3:
    DELAYS = ["-1", "0"]
BASE_CONF_EXTRA = CONF_EXTRA


def loadgen_args(scenario):
    """the load generator's URL and options for a scenario, and httpd's
    configuration for it"""
    url = "http://127.0.0.1:%d/b" % FRONT
    if scenario == "up":
        return [url, "-upload", str(SIZE), "-wchunk", str(CHUNK), "-wdelay", PAUSE], ""
    if scenario == "up-crawl":
        return [url, "-upload", str(CRAWL_SIZE), "-wchunk", str(CRAWL_CHUNK),
                "-wdelay", CRAWL_PAUSE], ""
    if scenario == "down-crawl":
        return [url + "?s=%d&c=%d" % (CRAWL_SIZE, CHUNK), "-rchunk", str(CRAWL_CHUNK),
                "-rdelay", CRAWL_PAUSE, "-rcvbuf", str(CRAWL_CHUNK)], \
            "SendBufferSize %d" % CRAWL_CHUNK
    url += "?s=%d&c=%d" % (SIZE, CHUNK)
    if scenario == "down-slow":
        return [url, "-rchunk", str(CHUNK), "-rdelay", PAUSE], ""
    if scenario == "down-fast":
        return [url, "-rchunk", str(CHUNK)], ""
    raise SystemExit("unknown scenario %s" % scenario)


backend = subprocess.Popen(pinned(BACKEND_CPUS, [os.path.join(here, "backend"),
                                                 "-addr", "127.0.0.1:%d" % BACK]))
time.sleep(0.5)
print("clients %d, %ss per run, 8 threads, pool max=%s, %d-byte bodies in %d-byte chunks,"
      " %s between the slow reads and the upload writes (crawl: %d bytes, %d-byte chunks"
      " every %s); cpu = httpd tree CPU ms per MB, cs = httpd context switches per MB"
      % (CLIENTS, SECONDS, POOLMAX, SIZE, CHUNK, PAUSE, CRAWL_SIZE, CRAWL_CHUNK,
         CRAWL_PAUSE))
try:
    for delay in DELAYS:
        for scenario in SCENARIOS:
            args, conf = loadgen_args(scenario)
            url, opts = args[0], args[1:]
            # httpd per scenario, for its configuration (start_httpd() reads CONF_EXTRA)
            CONF_EXTRA = BASE_CONF_EXTRA + "\n" + conf
            p = start_httpd(delay)
            try:
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
                print("delay %-5s %-10s: %s | cpu %.1f ms/MB | cs %.1f/MB"
                      % (delay, scenario, out, cpu, cs), flush=True)
                if st:
                    st.wait()
                    print("    syscalls/req: " + strace_per_req(n), flush=True)
            finally:
                stop_httpd(p)
finally:
    backend.terminate()
    backend.wait(5)
