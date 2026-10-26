"""MPM queuing scenarios: a background load and open-loop probes against
mod_aptest's "aptest-queue" handler, client-side latencies (connect
included) and the server's backlog stats (mpm_event's "backlog sojourn"
lines) aggregated over the measured window, with httpd's CPU use.

usage: python3 -I queue.py HTTPD_PREFIX APTEST_SO WORKDIR [scenario...]
env: CONF_EXTRA (appended to the httpd.conf, e.g. "AsyncRequestWorkerFactor 4"),
THREADS (the threads per child of the scenarios not setting theirs, 4 by
default), FLOOD (the flood's query in the "progress" scenario, "cpu=1" by
default)
"""

import calendar
import os
import re
import signal
import subprocess
import sys
import threading
import time

prefix, aptest, work = sys.argv[1], sys.argv[2], sys.argv[3]
only = sys.argv[4:]
here = os.path.dirname(os.path.abspath(__file__))
LOADGEN = os.path.join(here, "loadgen")
PORT = 18510
WARM, SECONDS = 2, 10
TICK = os.sysconf("SC_CLK_TCK")
HTTPD_CPUS, LOADGEN_CPUS = "0-3", "6,7"
CONF_EXTRA = os.environ.get("CONF_EXTRA", "")
THREADS = int(os.environ.get("THREADS", "4"))
FLOOD = os.environ.get("FLOOD", "cpu=1")

CONF = """
ServerRoot "{prefix}"
Listen 127.0.0.1:{port}
PidFile "{work}/httpd.pid"
ErrorLog "{work}/error_log"
LogLevel warn mpm_event:trace2
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule aptest_module {aptest}
ServerName localhost
StartServers {start}
ServerLimit {children}
ThreadLimit {threads}
ThreadsPerChild {threads}
MaxRequestWorkers {workers}
MinSpareThreads {minspare}
MaxSpareThreads {workers}
MaxKeepAliveRequests 0
KeepAliveTimeout 30
ListenBacklog 4096
{extra}
<Location "/q">
    SetHandler aptest-queue
</Location>
"""

# group: (label, query, kind, amount, keepalive)
#   kind "c": closed loop with amount clients; "rate": open loop at amount/s;
#   "burst": amount new connections every 2s for 300ms
PROBES = ("probes", "cpu=0", "rate", 20, False)
SCENARIOS = {
    "burst": dict(groups=[("bursts", "cpu=2", "burst", 100, False), PROBES]),
    "overload-cpu": dict(groups=[("bg", "cpu=5", "c", 64, True), PROBES]),
    "blocked": dict(groups=[("bg", "block=200", "c", 16, True), PROBES]),
    "async-mix": dict(groups=[("bg", "suspend=100", "c", 200, True), PROBES]),
    "progress": dict(groups=[("inprogress", "suspend=20", "c", 32, True),
                             ("flood", FLOOD, "c", 64, False)]),
    # One child at start, the second spawned once the first one's threads are
    # all blocked (MinSpareThreads): the probes should go to the second one.
    "two-children": dict(children=2, start=1, minspare=4,
                         groups=[("bg", "block=200", "c", 4, True), PROBES]),
}


def tree_cpu(pid):
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


def start_httpd(children, threads, extra, start=None, minspare=1):
    os.makedirs(work, exist_ok=True)
    with open(os.path.join(work, "httpd.conf"), "w") as f:
        f.write(CONF.format(prefix=prefix, port=PORT, work=work, aptest=aptest,
                            children=children, threads=threads,
                            start=start or children, minspare=minspare,
                            workers=children * threads, extra=extra))
    open(os.path.join(work, "error_log"), "w").close()
    p = subprocess.Popen(["taskset", "-c", HTTPD_CPUS, os.path.join(prefix, "bin", "httpd"),
                          "-f", os.path.join(work, "httpd.conf"), "-DFOREGROUND"])
    for _ in range(100):
        r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                            "http://127.0.0.1:%d/q" % PORT], capture_output=True, text=True)
        if r.stdout == "200":
            if p.poll() is not None or not subprocess.run(
                    ["pgrep", "-P", str(p.pid)], capture_output=True).stdout:
                stop_httpd(p)
                raise SystemExit("our httpd isn't the one running (leftover?)")
            return p
        time.sleep(0.05)
    stop_httpd(p)
    raise SystemExit("httpd didn't start")


def stop_httpd(p):
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(15)
    except subprocess.TimeoutExpired:
        for kid in subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True,
                                  text=True).stdout.split():
            os.kill(int(kid), signal.SIGKILL)
        p.kill()
        p.wait(10)


def loadgen(label, query, kind, amount, keepalive, dur, warm):
    args = ["taskset", "-c", LOADGEN_CPUS, LOADGEN, "-label", label,
            "-url", "http://127.0.0.1:%d/q?%s" % (PORT, query),
            "-d", "%gs" % dur, "-w", "%gs" % warm, "-k=%s" % ("true" if keepalive else "false")]
    if kind == "rate":
        args += ["-rate", str(amount), "-c", "64"]
    else:
        args += ["-c", str(amount)]
    return subprocess.Popen(args, stdout=subprocess.PIPE, text=True)


def parse_lg(out):
    m = re.search(r"rps (\d+) errors (\d+) p50 ([\d.]+)ms p99 ([\d.]+)ms max ([\d.]+)ms n (\d+)", out)
    return dict(rps=int(m.group(1)), errors=int(m.group(2)), p50=float(m.group(3)),
                p99=float(m.group(4)), max=float(m.group(5)), n=int(m.group(6))) if m else None


def run_bursts(label, query, amount, results, t_end):
    """A burst of `amount` new connections every 2s, for 300ms each"""
    outs = []
    while time.monotonic() < t_end:
        t0 = time.monotonic()
        p = loadgen(label, query, "c", amount, False, 0.3, 0)
        outs.append(parse_lg(p.communicate()[0]))
        time.sleep(max(0, 2 - (time.monotonic() - t0)))
    outs = [o for o in outs if o]
    n = sum(o["n"] for o in outs)
    results[label] = dict(rps=n / SECONDS, errors=sum(o["errors"] for o in outs),
                          p50=max(o["p50"] for o in outs) if outs else 0,
                          p99=max(o["p99"] for o in outs) if outs else 0,
                          max=max(o["max"] for o in outs) if outs else 0, n=n,
                          note="per-burst worst p50/p99")


LINE = re.compile(r"^\[([^\]]+)\].*backlog sojourn:(.*); accept off (\d+) times, (\d+)ms"
                  r"(?:, backstop (\d+))?")
CLASS = re.compile(r"(\w+):n=(\d+),avg=(\d+)us,p50<(\d+)us,p99<(\d+)us,max=(\d+)us")


def server_stats(t_from, t_to):
    """Aggregate the per-second backlog lines logged within [t_from, t_to]
    (wall clock), all children together."""
    classes, toggles, off_ms, backstops, lines = {}, 0, 0, 0, 0
    with open(os.path.join(work, "error_log")) as f:
        for line in f:
            m = LINE.match(line)
            if not m:
                continue
            # httpd logs in UTC here
            ts = calendar.timegm(time.strptime(re.sub(r"\.\d+", "", m.group(1)),
                                               "%a %b %d %H:%M:%S %Y"))
            if not (t_from <= ts <= t_to):
                continue
            lines += 1
            toggles += int(m.group(3))
            off_ms += int(m.group(4))
            backstops += int(m.group(5) or 0)
            for c in CLASS.finditer(m.group(2)):
                name, n, avg, p50, p99, mx = c.group(1), *map(int, c.groups()[1:])
                st = classes.setdefault(name, dict(n=0, sum=0, p99=0, max=0))
                st["n"] += n
                st["sum"] += n * avg
                st["p99"] = max(st["p99"], p99)
                st["max"] = max(st["max"], mx)
    return classes, toggles, off_ms, backstops, lines


def run(name, sc):
    children = sc.get("children", 1)
    threads = sc.get("threads", THREADS)
    extra = sc.get("extra", "") + "\n" + CONF_EXTRA
    p = start_httpd(children, threads, extra, sc.get("start"),
                    sc.get("minspare", 1))
    try:
        results, threads_ = {}, []
        procs = []
        t_start = time.monotonic()
        for g in sc["groups"]:
            label, query, kind, amount, keepalive = g
            if kind == "burst":
                th = threading.Thread(target=run_bursts,
                                      args=(label, query, amount, results,
                                            t_start + WARM + SECONDS))
                th.start()
                threads_.append(th)
            else:
                procs.append(loadgen(label, query, kind, amount, keepalive, SECONDS, WARM))
        time.sleep(WARM)
        w0, c0 = time.time(), tree_cpu(p.pid)
        time.sleep(SECONDS)
        w1, c1 = time.time(), tree_cpu(p.pid)
        for pr in procs:
            out = pr.communicate()[0].strip()
            results[out.split()[0]] = parse_lg(out)
        for th in threads_:
            th.join()
        time.sleep(1.2)  # the last stats line
        classes, toggles, off_ms, backstops, lines = server_stats(w0, w1 + 1)
    finally:
        stop_httpd(p)

    cpu = (c1 - c0) / (w1 - w0) / 4 * 100
    print("== %s (%d child%s x %d threads): httpd CPU %.0f%% of 4 cores, "
          "accept off %d times (backstop %d), %dms (in %d stats lines)"
          % (name, children, "ren" if children > 1 else "", threads, cpu, toggles,
             backstops, off_ms, lines))
    for label, r in results.items():
        if r:
            print("   %-10s %6.0f req/s  p50 %8.2fms  p99 %8.2fms  max %8.2fms  errors %d %s"
                  % (label, r["rps"], r["p50"], r["p99"], r["max"], r["errors"],
                     r.get("note", "")))
    for cname in ("new", "keepalive", "continuation", "waitio", "write", "linger", "timer"):
        st = classes.get(cname)
        if st and st["n"]:
            print("   backlog %-9s n=%-7d avg %7.0fus  p99 <%7dus  max %7dus"
                  % (cname, st["n"], st["sum"] / st["n"], st["p99"], st["max"]))
    sys.stdout.flush()


for name, sc in SCENARIOS.items():
    if only and name not in only:
        continue
    run(name, sc)
