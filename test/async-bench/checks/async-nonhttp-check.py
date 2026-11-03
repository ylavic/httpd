"""Check that a backend answering with something else than an HTTP/1.x status
line (another protocol, or an HTTP/0.9 response, which mod_proxy_http never
asks for) gives a 502, none of its bytes passed on, in both modes.

usage: MODES="sync async" python3 -I async-nonhttp-check.py HTTPD_PREFIX WORKDIR
"""

import os
import re
import socket
import threading

here = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(here, "async-proto-check.py")).read().split("report = []")[0])

RAW = BACKEND + 10
CONF += """
<Location "/raw">
    ProxyPass "http://127.0.0.1:%d/raw"
    {asyncconf}
</Location>
""" % RAW


def raw_backend():
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", RAW))
    ls.listen(16)
    while True:
        c, _ = ls.accept()
        try:
            c.recv(65536)
            c.sendall(b"SSH-2.0-RAWBYTES not an HTTP response\r\n")
        except OSError:
            pass
        c.close()


threading.Thread(target=raw_backend, daemon=True).start()

report = []
MODES = {"sync": "ProxyAsyncDelay -1", "async": "ProxyAsyncDelay 0\n    ProxyAsyncIdleTimeout 2"}
for mode in os.environ.get("MODES", "sync async").split():
    p = start(MODES[mode])
    try:
        st, body = get("/raw/x", timeout=10)
        # The error page quotes the status line (escaped, as for any corrupt
        # one), the backend's bytes are not the response's body
        report.append(("%s: non-HTTP backend" % mode, st == 502
                       and not body.startswith(b"SSH-2.0") and b"502 Proxy Error" in body,
                       "status %s, body %r" % (st, body[:40])))
    finally:
        result = stop(p)
    with open(os.path.join(work, "error_log")) as f:
        log = f.read()
    report.append(("%s: corrupt status line logged, stopped" % mode,
                   "Corrupt status line" in log and result == "stopped",
                   result))

failed = 0
for name, ok, info in report:
    print("%-55s %s  %s" % (name, "ok" if ok else "FAIL", info))
    failed += not ok
print("RESULT: %s" % ("PASS" if not failed else "%d FAILED" % failed))
raise SystemExit(1 if failed else 0)
