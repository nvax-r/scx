#!/usr/bin/env python3
"""
reader.py — Read and summarize scx_invariant binary trace files.

Usage: python3 reader.py <trace.scxi>

The on-disk format definitions and parsing primitives live in
`trace.py` (single source of truth shared with future tools such as
`report.py`). This module owns only the text-mode CLI and the
human-readable summary output.

2026-05-12: SECTION_PROCS (0x0002) is gone. The pid → comm mapping is
reconstructed here from the EVT_PROC_NEW event stream — see
`build_proc_table()` below. Two new sections (ProcMaps 0x0004,
ProcStacks 0x0005) are loaded by `trace.read_sections` and the
summary now includes per-PID maps counts and the stack-id table size.
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


def build_proc_table(events):
    """Reconstruct the pid → {comm, ppid, execs} table from the event stream.

    Pass 1 of the two-pass analyzer (design §6). Iterates the event
    list in arrival order; EVT_PROC_NEW seeds an entry, EVT_PROC_EXEC
    bumps the per-PID exec counter so downstream consumers can flag
    `stale-maps after exec` PIDs.

    EVT_PROC_EXEC also overwrites `comm` when the payload carries
    one (post-2026-05-12 layout, 40 B on disk). Old 24 B EVT_PROC_EXEC
    records decode without a `comm` field and we leave the prior
    value intact. This is what stops a `record -- <cmd>` workload
    from rendering under the recorder's pre-exec comm forever —
    see work/changelog.md 2026-05-12 (post-exec comm refresh).

    PIDs that appear only in scheduling events (running/stopping/...)
    without a preceding EVT_PROC_NEW are NOT added here — they get a
    placeholder elsewhere if needed (`report.py` tags them
    `partial-identity`).
    """
    table = {}
    for evt_type, payload in events:
        parsed = parse_event(evt_type, payload)
        if not parsed:
            continue
        pid = parsed["pid"]
        if evt_type == EVT_PROC_NEW:
            table[pid] = {
                "comm": parsed.get("comm", ""),
                "ppid": parsed.get("ppid", 0),
                "execs": 0,
            }
        elif evt_type == EVT_PROC_EXEC:
            entry = table.setdefault(pid, {"comm": "?", "ppid": 0, "execs": 0})
            entry["execs"] += 1
            new_comm = parsed.get("comm")
            if new_comm:
                entry["comm"] = new_comm
    return table


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
    topology, raw_events, proc_maps, proc_stacks, proc_flags, _raw_log = (
        read_sections(data, hdr["header_size"])
    )

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

    # Process table — reconstructed from EVT_PROC_NEW + EVT_PROC_EXEC
    procs_table = build_proc_table(raw_events)
    procs = {pid: entry["comm"] for pid, entry in procs_table.items()}
    if procs:
        print(f"=== Process Table ({len(procs)} entries from EVT_PROC_NEW) ===")
        named = {pid: name for pid, name in procs.items() if name}
        unnamed = len(procs) - len(named)
        for i, (pid, name) in enumerate(sorted(named.items())[:20]):
            execs = procs_table[pid]["execs"]
            tag = f" (execs={execs})" if execs else ""
            print(f"  {pid:>8}  {name}{tag}")
        if len(named) > 20:
            print(f"  ... and {len(named) - 20} more")
        if unnamed:
            print(f"  ({unnamed} PIDs with no comm captured)")
        print()

    # New sections — quick summary so the reader is useful as a
    # producer-side smoke check.
    if proc_maps:
        n_pids = len(proc_maps)
        n_total = sum(len(v) for v in proc_maps.values())
        n_anon = sum(1 for v in proc_maps.values() for e in v if not e.path)
        # Per-PID flag tallies (added 2026-05-12). `inherited` is the
        # interesting one: it's the dominant outcome for sub-ms forks
        # where /proc/<pid> died before we could read it and the
        # recorder fell back to the parent's executable mappings.
        n_inherited = sum(
            1 for f in proc_flags.values()
            if f & PROC_FLAG_INHERITED_FROM_PARENT
        )
        n_partial = sum(
            1 for f in proc_flags.values()
            if f & PROC_FLAG_PARTIAL_IDENTITY
        )
        n_no_maps = sum(
            1 for f in proc_flags.values()
            if f & PROC_FLAG_NO_MAPS
        )
        print(f"=== Proc Maps ({n_pids} PIDs, {n_total} executable mappings, "
              f"{n_anon} anon) ===")
        if n_inherited or n_partial or n_no_maps:
            print(f"  flags: {n_inherited} inherited-from-parent, "
                  f"{n_partial} partial-identity, {n_no_maps} no-maps")
        # Top 5 PIDs by mapping count
        top = sorted(proc_maps.items(), key=lambda kv: -len(kv[1]))[:5]
        for pid, entries in top:
            comm = procs.get(pid, "?")
            f = proc_flags.get(pid, 0)
            tag = ""
            if f & PROC_FLAG_INHERITED_FROM_PARENT:
                tag += " [inherited]"
            if f & PROC_FLAG_PARTIAL_IDENTITY:
                tag += " [partial]"
            if f & PROC_FLAG_NO_MAPS:
                tag += " [no-maps]"
            print(f"  pid={pid:<8} comm={comm:<16} maps={len(entries)}{tag}")
        print()

    if proc_stacks:
        n_stacks = len(proc_stacks)
        n_frames = sum(len(v) for v in proc_stacks.values())
        avg_depth = (n_frames / n_stacks) if n_stacks else 0
        print(f"=== Proc Stacks ({n_stacks} unique stacks, "
              f"avg depth {avg_depth:.1f}) ===")
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
