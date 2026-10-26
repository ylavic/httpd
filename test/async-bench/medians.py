"""Median of each (delay, backend) cell, or of each tunnel count, over the given
bench.py/tunnelbench.py logs (round*.log by default).

usage: python3 -I medians.py [LOG...]
"""
import glob
import re
import statistics
import sys

cells, tunnels = {}, {}
for path in sys.argv[1:] or sorted(glob.glob("round*.log")):
    for line in open(path):
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
