"""Check the requests waiting for a backend connection of an exhausted pool
without holding a thread (ap_proxy_acquire_connection_ex(), the MPM's notifier).

usage: MODES="sync async" python3 -I async-pool-check.py HTTPD_PREFIX WORKDIR
"""

import os
import subprocess
import threading
import time

here = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(here, "async-proto-check.py")).read().split("\nreport = []")[0])

CONF += """
<Location "/p2">
    ProxyPass "http://127.0.0.1:{backend}/p2" max=2
    {asyncconf}
</Location>
<Location "/p4">
    ProxyPass "http://127.0.0.1:{backend}/p4" max=4
    {asyncconf}
</Location>
<Location "/acq">
    ProxyPass "http://127.0.0.1:{backend}/acq" max=2 acquire=500
    {asyncconf}
</Location>
"""


def many(path, n, delay, timeout=30):
    res = [None] * n

    def one(i):
        try:
            res[i] = get("%s?d=%s&i=%d" % (path, delay, i), timeout=timeout)
        except Exception as e:
            res[i] = (type(e).__name__, b"")
    t0 = time.monotonic()
    th = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    for t in th:
        t.start()
    for t in th:
        t.join()
    ok = all(r[0] == 200 and b"i=%d" % i in r[1] for i, r in enumerate(res) if r[0] == 200)
    # statuses (int) and exceptions' names (str) mixed: sort them as strings
    return time.monotonic() - t0, sorted((r[0] for r in res), key=str), ok


def child_fds():
    kids = subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True,
                          text=True).stdout.split()
    return sum(len(os.listdir("/proc/%s/fd" % k)) for k in kids)


def summary(st):
    return {s: st.count(s) for s in sorted(set(st), key=str)}


report = []
MODES = {"sync": "ProxyAsyncDelay -1", "async": "ProxyAsyncDelay 0"}
for mode in os.environ.get("MODES", "sync async").split():
    p = start(MODES[mode])
    try:
        # max=2, 10 requests of 1s
        t, st, ok = many("/p2", 10, 1)
        report.append("%s: max=2, 10 requests of 1s: %.1fs %s bodies ok %s"
                      % (mode, t, summary(st), ok))
        # max=4
        t, st, ok = many("/p4", 10, 1)
        report.append("%s: max=4, 10 requests of 1s: %.1fs %s bodies ok %s"
                      % (mode, t, summary(st), ok))
        # acquire=500ms: the requests waiting longer get a 503
        t, st, ok = many("/acq", 6, 1)
        report.append("%s: max=2 acquire=500, 6 requests of 1s: %.1fs %s" % (mode, t, summary(st)))
        # a burst of short requests: no wakeup lost
        t, st, ok = many("/p2", 300, 0.01, timeout=60)
        report.append("%s: max=2, 300 requests of 10ms: %.1fs %s bodies ok %s"
                      % (mode, t, summary(st), ok))
        # the child's fds while 10 requests wait for the pool, vs idle
        idle = child_fds()
        th = threading.Thread(target=many, args=("/p2", 10, 2))
        th.start()
        time.sleep(1)
        busy = child_fds()
        th.join()
        report.append("%s: child fds idle %d, with 10 requests (2 connected) %d"
                      % (mode, idle, busy))
        with open(os.path.join(work, "error_log")) as f:
            log = f.read()
        report.append("%s: pool waits (async) %d, available %d, timeouts %d, crashes %d" % (
            mode, log.count("] proxy: waiting for a connection to"),
            log.count("available (async)"),
            log.count("timeout waiting for a connection"),
            log.count("exit signal")))
    finally:
        report.append("%s: %s" % (mode, stop(p)))
backend.shutdown()
print("\n".join(report))
