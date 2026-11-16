"""Check the balancer with async requests: failover, failonstatus,
failontimeout (post_request at the real end of the request).

usage: MODES="sync async" python3 -I async-balancer-check.py HTTPD_PREFIX WORKDIR
"""

import os
import time
from urllib.parse import urlparse

here = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(here, "async-proto-check.py")).read().split("\nreport = []")[0])

CONF = CONF.replace("LoadModule proxy_module", """LoadModule slotmem_shm_module modules/mod_slotmem_shm.so
LoadModule proxy_module""").replace("LoadModule proxy_http_module modules/mod_proxy_http.so", """LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule proxy_balancer_module modules/mod_proxy_balancer.so
LoadModule lbmethod_byrequests_module modules/mod_lbmethod_byrequests.so""")
CONF += """
<Proxy "balancer://over">
    BalancerMember "http://192.0.2.1:18431/m2" connectiontimeout=1 retry=60
    BalancerMember "http://127.0.0.1:{backend}/m2" retry=60
    ProxySet lbmethod=byrequests maxattempts=1
</Proxy>
<Proxy "balancer://status">
    BalancerMember "http://127.0.0.1:{backend}/m1" retry=60
    BalancerMember "http://127.0.0.1:{backend}/m2" retry=60
    ProxySet lbmethod=byrequests failonstatus=503
</Proxy>
<Proxy "balancer://tmo">
    BalancerMember "http://127.0.0.1:{backend}/m1" retry=60 timeout=3
    BalancerMember "http://127.0.0.1:{backend}/m2" retry=60 timeout=3
    ProxySet lbmethod=byrequests failontimeout=on
</Proxy>
<Location "/over">
    ProxyPass "balancer://over"
    {asyncconf}
</Location>
<Location "/status">
    ProxyPass "balancer://status"
    {asyncconf}
</Location>
<Location "/tmo">
    ProxyPass "balancer://tmo"
    {asyncconf}
</Location>
"""


def member_GET(self):
    path = urlparse(self.path).path
    if path.startswith("/m1"):
        time.sleep(5 if "/slowfail" in path else 0.3)
        code, body = 503, b"m1 down\n"
    else:
        time.sleep(0.3)
        code, body = 200, b"m2\n"
    self.send_response(code)
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)


Slow.do_GET = member_GET

report = []
MODES = {"sync": "ProxyAsyncDelay -1", "async": "ProxyAsyncDelay 0\n    ProxyAsyncIdleTimeout 2"}
for mode in os.environ.get("MODES", "sync async").split():
    p = start(MODES[mode])
    try:
        t0 = time.monotonic()
        st, body = get("/over/x")
        report.append("%s: failover from an unreachable member: %s %r after %.1fs"
                      % (mode, st, body.strip(), time.monotonic() - t0))
        seq = [get("/status/x?i=%d" % i) for i in range(6)]
        report.append("%s: failonstatus=503, 6 requests: %s" % (
            mode, [(s, b.strip().decode()) for s, b in seq]))
        t0 = time.monotonic()
        first = get("/tmo/slowfail")
        el = time.monotonic() - t0
        seq = [get("/tmo/slowfail?i=%d" % i)[0] for i in range(4)]
        report.append("%s: failontimeout, first %s after %.1fs, then: %s"
                      % (mode, first[0], el, seq))
        with open(os.path.join(work, "error_log")) as f:
            log = f.read()
        report.append("%s: forced into error: failonstatus %d, failontimeout %d; crashes %d"
                      % (mode, log.count("matching 'failonstatus'"),
                         log.count("'failontimeout' parameter"), log.count("exit signal")))
    finally:
        report.append("%s: %s" % (mode, stop(p)))
backend.shutdown()
print("\n".join(report))
