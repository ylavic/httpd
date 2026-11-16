"""Median of each (delay, backend) cell, of each tunnel count, or of each (delay,
scenario) cell, over the given bench.py/tunnelbench.py/bodybench.py logs
(round*.log by default).

usage: python3 -I medians.py [LOG...]
"""
import glob
import re
import statistics
import sys

cells, tunnels, bodies = {}, {}, {}
for path in sys.argv[1:] or sorted(glob.glob("round*.log")):
    for line in open(path):
        m = re.match(r"delay (\S+)\s+(\S+)\s*: rps (\d+) errors (\d+) p50 ([\d.]+)ms "
                     r"p99 ([\d.]+)ms .* mbps ([\d.]+) \| cpu ([\d.]+) ms/MB \| cs ([\d.]+)",
                     line)
        if m:
            bodies.setdefault((m.group(1), m.group(2)), []).append(
                tuple(float(x) for x in m.groups()[2:]))
            continue
        m = re.match(r"delay (\S+)\s+backend\s+(\d+)ms: rps (\d+) errors (\d+) p50 ([\d.]+)ms "
                     r"p99 ([\d.]+)ms .* \| cpu ([\d.]+)(?: ms/1k req \| cs ([\d.]+))?", line)
        if m:
            key = (m.group(1), int(m.group(2)))
            cells.setdefault(key, []).append(tuple(float(x or 0) for x in m.groups()[2:]))
            continue
        m = re.match(r"tunnels (\d+) mps (\d+) errors (\d+) p50 ([\d.]+)ms p99 ([\d.]+)ms "
                     r".* \| cpu ([\d.]+) ms/1k msg \| cs ([\d.]+)", line)
        if m:
            tunnels.setdefault(int(m.group(1)), []).append(
                tuple(float(x) for x in m.groups()[1:]))

if cells:
    print("%-6s %8s | %8s %6s %8s %8s %9s %6s | %s" % (
        "delay", "backend", "req/s", "errs", "p50 ms", "p99 ms", "cpu/1k", "cs/req",
        "req/s per round"))
    order = ["-1", "0", "1ms", "10ms"]
    for ms in sorted(set(k[1] for k in cells)):
        for d in order + sorted(set(k[0] for k in cells) - set(order)):
            v = cells.get((d, ms))
            if not v:
                continue
            med = [statistics.median(x[i] for x in v) for i in range(6)]
            print("%-6s %6dms | %8.0f %6.0f %8.2f %8.2f %9.1f %6.1f | %s" % (
                d, ms, med[0], med[1], med[2], med[3], med[4], med[5],
                [int(x[0]) for x in v]))
        print()
if tunnels:
    print("%8s | %8s %6s %8s %8s %9s %6s" % ("tunnels", "msg/s", "errs", "p50 ms", "p99 ms",
                                              "cpu/1k", "cs/msg"))
    for t in sorted(tunnels):
        med = [statistics.median(x[i] for x in tunnels[t]) for i in range(6)]
        print("%8d | %8.0f %6.0f %8.2f %8.2f %9.1f %6.1f" % (t, *med))
if bodies:
    print("%-6s %-9s | %6s %6s %8s %8s %7s %7s %6s" % (
        "delay", "scenario", "req/s", "errs", "p50 ms", "p99 ms", "MB/s", "cpu/MB", "cs/MB"))
    for key in sorted(bodies, key=lambda k: (k[1], k[0] != "-1", k[0])):
        med = [statistics.median(x[i] for x in bodies[key]) for i in range(7)]
        print("%-6s %-9s | %6.0f %6.0f %8.2f %8.2f %7.1f %7.2f %6.1f" % (*key, *med))
