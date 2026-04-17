#!/usr/bin/env python3
"""
reader.py — Read and summarize scx_invariant binary trace files.

Usage: python3 reader.py <trace.scxi>
"""

import struct
import sys
from collections import defaultdict
from pathlib import Path

# --- File format constants ---
MAGIC = b"SCXI"
SECTION_TOPOLOGY = 0x0001
SECTION_PROCS    = 0x0002
SECTION_EVENTS   = 0x0003

EVT_RUNNING   = 1
EVT_STOPPING  = 2
EVT_RUNNABLE  = 3
EVT_QUIESCENT = 4
EVT_TICK      = 5

EVT_NAMES = {
    EVT_RUNNING:   "RUNNING",
    EVT_STOPPING:  "STOPPING",
    EVT_RUNNABLE:  "RUNNABLE",
    EVT_QUIESCENT: "QUIESCENT",
    EVT_TICK:      "TICK",
}

FLAG_MIGRATED    = 1 << 0
FLAG_SYNC_WAKEUP = 1 << 1
FLAG_VOLUNTARY   = 1 << 2

ARCH_NAMES = {0: "unknown", 1: "aarch64", 2: "x86_64"}

# --- Struct formats (aarch64 LE) ---
# Common event header: timestamp_ns(u64) pid(u32) tgid(u32) cpu(u32) event_type(u16) flags(u16)
HDR_FMT = "<QIIIHH"  # 24 bytes
HDR_SIZE = struct.calcsize(HDR_FMT)

# evt_running payload after header (64 bytes):
#   runq_wait_ns(u64) waker_pid(u32) waker_tgid(u32) waker_flags(u16) cpu_perf(u16)
#   prev_cpu(i32) wake_flags(u64) pmc_inst(u64) pmc_cyc(u64) pmc_l2(u64) pmc_stall(u64)
RUNNING_FMT = "<QIIHHiQQQQQ"
RUNNING_SIZE = struct.calcsize(RUNNING_FMT)

# evt_stopping payload after header (64 bytes):
#   runtime_ns(u64) pmc_inst(u64) pmc_cyc(u64) pmc_l2(u64) pmc_stall(u64)
#   slice_consumed(u64) slice_allocated(u64) voluntary(u8) pad(7 bytes)
STOPPING_FMT = "<QQQQQQQB7x"
STOPPING_SIZE = struct.calcsize(STOPPING_FMT)

# evt_runnable payload after header (16 bytes):
#   sleep_duration_ns(u64) enq_flags(u32) pad(u32)
RUNNABLE_FMT = "<QII"
RUNNABLE_SIZE = struct.calcsize(RUNNABLE_FMT)

# evt_quiescent payload after header (8 bytes):
#   deq_flags(u32) pad(u32)
QUIESCENT_FMT = "<II"
QUIESCENT_SIZE = struct.calcsize(QUIESCENT_FMT)


def decode_kernel_ver(v):
    major = (v >> 16) & 0xFFFF
    minor = (v >> 8) & 0xFF
    patch = v & 0xFF
    return f"{major}.{minor}.{patch}"


def read_header(data):
    """Parse the 64-byte file header."""
    if len(data) < 64:
        raise ValueError(f"File too small for header: {len(data)} bytes")
    if data[:4] != MAGIC:
        raise ValueError(f"Bad magic: {data[:4]!r} (expected {MAGIC!r})")

    version, header_size = struct.unpack_from("<HH", data, 4)
    flags, = struct.unpack_from("<I", data, 8)
    ts_start, ts_end = struct.unpack_from("<QQ", data, 12)
    hostname = data[28:56].split(b"\x00")[0].decode("utf-8", errors="replace")
    kernel_ver, = struct.unpack_from("<I", data, 56)
    arch, nr_cpus = struct.unpack_from("<HH", data, 60)

    return {
        "version": version,
        "header_size": header_size,
        "flags": flags,
        "ts_start": ts_start,
        "ts_end": ts_end,
        "hostname": hostname,
        "kernel_version": decode_kernel_ver(kernel_ver),
        "arch": ARCH_NAMES.get(arch, f"unknown({arch})"),
        "nr_cpus": nr_cpus,
    }


def read_sections(data, offset):
    """Parse sections: topology, events, process table."""
    topology = []
    events = []
    procs = {}

    while offset < len(data):
        if offset + 6 > len(data):
            break
        sec_type, sec_len = struct.unpack_from("<HI", data, offset)
        offset += 6

        if sec_type == SECTION_TOPOLOGY:
            end = offset + sec_len
            while offset + 16 <= end:
                cpu_id, llc_id, numa_id, max_freq, capacity, _pad = struct.unpack_from(
                    "<HHHHIi", data, offset
                )
                topology.append({
                    "cpu_id": cpu_id,
                    "llc_id": llc_id,
                    "numa_id": numa_id,
                    "max_freq_mhz": max_freq,
                    "capacity": capacity,
                })
                offset += 16

        elif sec_type == SECTION_EVENTS:
            # sec_len == 0 means until next section header or EOF
            # We read TLV events: [event_type: u16][payload_len: u16][payload]
            # Known event payload sizes (full struct including header)
            KNOWN_SIZES = {88, 40, 32, 64}
            while offset + 4 <= len(data):
                evt_type, payload_len = struct.unpack_from("<HH", data, offset)

                # Detect section boundary: valid events have known payload sizes
                # and event types 1-5.  If either is wrong, we hit the next section.
                if evt_type not in (EVT_RUNNING, EVT_STOPPING, EVT_RUNNABLE,
                                     EVT_QUIESCENT, EVT_TICK):
                    break
                if payload_len not in KNOWN_SIZES:
                    break

                offset += 4
                if offset + payload_len > len(data):
                    break

                payload = data[offset : offset + payload_len]
                events.append((evt_type, payload))
                offset += payload_len


        elif sec_type == SECTION_PROCS:
            end = offset + sec_len
            while offset + 20 <= end:
                pid, = struct.unpack_from("<I", data, offset)
                comm = data[offset + 4 : offset + 20].split(b"\x00")[0].decode(
                    "utf-8", errors="replace"
                )
                procs[pid] = comm
                offset += 20

        else:
            # Unknown section — skip if we can
            if sec_len > 0:
                offset += sec_len
            else:
                break

    return topology, events, procs


def parse_event(evt_type, payload):
    """Parse a single event payload into a dict."""
    if len(payload) < HDR_SIZE:
        return None
    hdr = struct.unpack_from(HDR_FMT, payload, 0)
    result = {
        "timestamp_ns": hdr[0],
        "pid": hdr[1],
        "tgid": hdr[2],
        "cpu": hdr[3],
        "event_type": hdr[4],
        "flags": hdr[5],
    }

    body = payload[HDR_SIZE:]

    if evt_type == EVT_RUNNING and len(body) >= RUNNING_SIZE:
        fields = struct.unpack_from(RUNNING_FMT, body, 0)
        result.update({
            "runq_wait_ns": fields[0],
            "waker_pid": fields[1],
            "waker_tgid": fields[2],
            "waker_flags": fields[3],
            "cpu_perf": fields[4],
            "prev_cpu": fields[5],
            "wake_flags": fields[6],
            "pmc_instructions": fields[7],
            "pmc_cycles": fields[8],
            "pmc_l2_misses": fields[9],
            "pmc_stall_backend": fields[10],
        })

    elif evt_type == EVT_STOPPING and len(body) >= STOPPING_SIZE:
        fields = struct.unpack_from(STOPPING_FMT, body, 0)
        result.update({
            "runtime_ns": fields[0],
            "pmc_instructions": fields[1],
            "pmc_cycles": fields[2],
            "pmc_l2_misses": fields[3],
            "pmc_stall_backend": fields[4],
            "slice_consumed_ns": fields[5],
            "slice_allocated_ns": fields[6],
            "voluntary": fields[7],
        })

    elif evt_type == EVT_RUNNABLE and len(body) >= RUNNABLE_SIZE:
        fields = struct.unpack_from(RUNNABLE_FMT, body, 0)
        result.update({
            "sleep_duration_ns": fields[0],
            "enq_flags": fields[1],
        })

    elif evt_type == EVT_QUIESCENT and len(body) >= QUIESCENT_SIZE:
        fields = struct.unpack_from(QUIESCENT_FMT, body, 0)
        result.update({
            "deq_flags": fields[0],
        })

    return result


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
