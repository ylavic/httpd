"""Check mod_status' ExtendedStatus totals across the children's exits: with
MaxConnectionsPerChild 2 the children exit and are replaced while requests
are served, and "Total Accesses" (?auto) never goes down (the counters of a
vacant scoreboard slot still count).

usage: python3 -I async-status-check.py HTTPD_PREFIX WORKDIR
"""

import os
import re
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
LoadModule status_module modules/mod_status.so
ServerName localhost
StartServers 2
ServerLimit 4
ThreadLimit 2
ThreadsPerChild 2
MaxRequestWorkers 8
MinSpareThreads 1
MaxSpareThreads 8
MaxConnectionsPerChild 2
ExtendedStatus On
KeepAlive Off
<Location "/server-status">
    SetHandler server-status
</Location>
{asyncconf}{passopts}
"""

def get_retry(path):
    """get(), again when the connection went to a child exiting meanwhile
    (accepted by its listening socket but not served: reset)"""
    for _ in range(5):
        try:
            return get(path, timeout=5)
        except (ConnectionError, OSError):
            time.sleep(0.1)
    return get(path, timeout=5)


report = []
p = start("")
try:
    totals, slots_vacated = [], 0
    for i in range(30):
        get_retry("/nothing?i=%d" % i)
        st, body = get_retry("/server-status?auto")
        m = re.search(rb"^Total Accesses: (\d+)$", body, re.M)
        totals.append(int(m.group(1)) if m else -1)
        time.sleep(0.05)
    drops = [(a, b) for a, b in zip(totals, totals[1:]) if b < a]
    report.append(("Total Accesses monotonic across children's exits",
                   not drops and totals[-1] > 0 and -1 not in totals,
                   "first %d last %d, drops %s" % (totals[0], totals[-1], drops[:3])))
    st, body = get_retry("/server-status?auto")
    report.append(("?auto without the Threads* fields", b"ThreadsIdle" not in body
                   and b"BusyWorkers:" in body, ""))
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
