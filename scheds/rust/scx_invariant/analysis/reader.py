#!/usr/bin/env python3
"""
reader.py — Read and summarize scx_invariant binary trace files.

Usage: python3 reader.py <trace.scxi>

The on-disk format definitions and parsing primitives live in
`trace.py` (single source of truth shared with future tools such as
`report.py`). This module owns only the text-mode CLI and the
human-readable summary output.
"""

import sys
from collections import defaultdict
from pathlib import Path

# `analysis/trace.py` shadows the stdlib `trace` module. When `reader.py`
# is run as a script, Python prepends the script's directory to
# `sys.path`, so `import trace` resolves to the sibling file. The
# explicit insert below mirrors `test_reader.py`'s pattern and protects
# the imported-as-module case (e.g. from a notebook in the repo root)
# from picking up stdlib `trace` instead.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from trace import *  # noqa: E402, F401, F403


def format_ns(ns):
    """Format nanoseconds into a human-readable string."""
    if ns < 1000:
        return f"{ns}ns"
    elif ns < 1_000_000:
        return f"{ns / 1000:.1f}us"
    elif ns < 1_000_000_000:
        return f"{ns / 1_000_000:.2f}ms"
    else:
        return f"{ns / 1_000_000_000:.3f}s"


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <trace.scxi>", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]
    data = Path(path).read_bytes()
    print(f"File: {path} ({len(data)} bytes)")
    print()

    # Parse header
    hdr = read_header(data)
    print("=== File Header ===")
    print(f"  Version:    {hdr['version']}")
    print(f"  Hostname:   {hdr['hostname']}")
    print(f"  Kernel:     {hdr['kernel_version']}")
    print(f"  Arch:       {hdr['arch']}")
    print(f"  CPUs:       {hdr['nr_cpus']}")
    if hdr["ts_start"] and hdr["ts_end"] and hdr["ts_end"] > hdr["ts_start"]:
        duration_ns = hdr["ts_end"] - hdr["ts_start"]
        print(f"  Duration:   {format_ns(duration_ns)}")
    print()

    # Parse sections
    topology, raw_events, procs = read_sections(data, hdr["header_size"])

    # Topology
    if topology:
        print(f"=== Topology ({len(topology)} CPUs) ===")
        numa_groups = defaultdict(list)
        for t in topology:
            numa_groups[t["numa_id"]].append(t)
        for numa_id in sorted(numa_groups):
            cpus = numa_groups[numa_id]
            llcs = set(c["llc_id"] for c in cpus)
            freq = cpus[0]["max_freq_mhz"] if cpus else 0
            print(f"  NUMA {numa_id}: {len(cpus)} CPUs, {len(llcs)} LLC(s), max {freq} MHz")
        print()

    # Process table
    if procs:
        print(f"=== Process Table ({len(procs)} entries) ===")
        named = {pid: name for pid, name in procs.items() if name}
        unnamed = len(procs) - len(named)
        # Show up to 20
        for i, (pid, name) in enumerate(sorted(named.items())[:20]):
            print(f"  {pid:>8}  {name}")
        if len(named) > 20:
            print(f"  ... and {len(named) - 20} more")
        if unnamed:
            print(f"  ({unnamed} PIDs with no /proc/comm at finalize)")
        print()

    # Events
    print(f"=== Events ({len(raw_events)} total) ===")
    type_counts = defaultdict(int)
    for evt_type, _ in raw_events:
        type_counts[evt_type] += 1
    for t in sorted(type_counts):
        print(f"  {EVT_NAMES.get(t, f'UNKNOWN({t})'):<12} {type_counts[t]:>10}")
    print()

    # Per-thread runtime analysis (from STOPPING events)
    thread_runtime = defaultdict(int)      # pid -> total runtime_ns
    thread_count = defaultdict(int)        # pid -> number of stopping events
    thread_migrations = defaultdict(int)   # pid -> migration count (from RUNNING)
    thread_runq_wait = defaultdict(int)    # pid -> total runq_wait_ns

    for evt_type, payload in raw_events:
        parsed = parse_event(evt_type, payload)
        if not parsed:
            continue

        pid = parsed["pid"]

        if evt_type == EVT_STOPPING:
            runtime = parsed.get("runtime_ns", 0)
            thread_runtime[pid] += runtime
            thread_count[pid] += 1

        elif evt_type == EVT_RUNNING:
            if parsed.get("flags", 0) & FLAG_MIGRATED:
                thread_migrations[pid] += 1
            thread_runq_wait[pid] += parsed.get("runq_wait_ns", 0)

    if thread_runtime:
        print("=== Top 20 Threads by Runtime ===")
        top = sorted(thread_runtime.items(), key=lambda x: x[1], reverse=True)[:20]
        print(f"  {'PID':>8}  {'Name':<16} {'Runtime':>12}  {'Runs':>8}  {'Avg':>10}  {'Migrations':>10}  {'RunqWait':>12}")
        print(f"  {'-'*8}  {'-'*16} {'-'*12}  {'-'*8}  {'-'*10}  {'-'*10}  {'-'*12}")
        for pid, runtime in top:
            name = procs.get(pid, "?")
            runs = thread_count[pid]
            avg = runtime // runs if runs > 0 else 0
            mig = thread_migrations.get(pid, 0)
            rqw = thread_runq_wait.get(pid, 0)
            print(
                f"  {pid:>8}  {name:<16} {format_ns(runtime):>12}  {runs:>8}  "
                f"{format_ns(avg):>10}  {mig:>10}  {format_ns(rqw):>12}"
            )
        print()

    # Sleep duration analysis (from RUNNABLE events)
    thread_sleep_total = defaultdict(int)
    thread_sleep_count = defaultdict(int)
    for evt_type, payload in raw_events:
        if evt_type != EVT_RUNNABLE:
            continue
        parsed = parse_event(evt_type, payload)
        if not parsed:
            continue
        sleep_ns = parsed.get("sleep_duration_ns", 0)
        if sleep_ns > 0:
            pid = parsed["pid"]
            thread_sleep_total[pid] += sleep_ns
            thread_sleep_count[pid] += 1

    if thread_sleep_total:
        print("=== Top 20 Threads by Total Sleep Duration ===")
        top = sorted(thread_sleep_total.items(), key=lambda x: x[1], reverse=True)[:20]
        print(f"  {'PID':>8}  {'Name':<16} {'TotalSleep':>12}  {'Wakeups':>8}  {'AvgSleep':>10}")
        print(f"  {'-'*8}  {'-'*16} {'-'*12}  {'-'*8}  {'-'*10}")
        for pid, total in top:
            name = procs.get(pid, "?")
            count = thread_sleep_count[pid]
            avg = total // count if count > 0 else 0
            print(f"  {pid:>8}  {name:<16} {format_ns(total):>12}  {count:>8}  {format_ns(avg):>10}")
        print()

    # Wakeup graph (from RUNNING events with waker data)
    waker_counts = defaultdict(int)
    for evt_type, payload in raw_events:
        if evt_type != EVT_RUNNING:
            continue
        parsed = parse_event(evt_type, payload)
        if parsed and parsed.get("waker_pid", 0) != 0:
            waker_counts[(parsed["waker_pid"], parsed["pid"])] += 1

    if waker_counts:
        print("=== Top 20 Wakeup Edges ===")
        top_edges = sorted(waker_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        for (waker, wakee), count in top_edges:
            waker_name = procs.get(waker, "?")
            wakee_name = procs.get(wakee, "?")
            print(f"  {waker_name}({waker}) -> {wakee_name}({wakee}): {count}")
        print()
    else:
        print("=== Wakeup Graph ===")
        print("  (no waker data recorded)")
        print()


if __name__ == "__main__":
    main()
