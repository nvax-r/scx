#!/usr/bin/env python3
"""
trace.py — `.scxi` binary trace format constants, struct layouts, and
parsing primitives for `scx_invariant`.

This module is the single source of truth for the on-disk format on the
consumer side. It mirrors the producer-side definitions in
`src/bpf/intf.h` and `src/output.rs`. Any format-affecting change must
update all three (`intf.h`, `output.rs`, `trace.py`) together — see
`docs/eval.md` "Format compatibility checklist".

Public surface (declared in `__all__`): file/section/event constants,
struct format strings + sizes, `decode_kernel_ver`, `read_header`,
`read_sections`, `parse_event`, and `UnsupportedVersionError`.

`reader.py` (text-mode CLI) and the upcoming `report.py` both consume
this module so the decoder lives in exactly one place.

Stdlib only — `struct`.
"""

import struct


__all__ = [
    # File / section / event identity
    "MAGIC",
    "SUPPORTED_VERSION",
    "SECTION_TOPOLOGY",
    "SECTION_PROCS",
    "SECTION_EVENTS",
    "EVT_RUNNING",
    "EVT_STOPPING",
    "EVT_RUNNABLE",
    "EVT_QUIESCENT",
    "EVT_NAMES",
    "EVT_SIZES",
    # Event-header flags
    "FLAG_MIGRATED",
    "FLAG_SYNC_WAKEUP",
    "FLAG_VOLUNTARY",
    # Misc lookup tables
    "ARCH_NAMES",
    # Struct layouts
    "HDR_FMT",
    "HDR_SIZE",
    "RUNNING_FMT",
    "RUNNING_SIZE",
    "STOPPING_FMT",
    "STOPPING_SIZE",
    "RUNNABLE_FMT",
    "RUNNABLE_SIZE",
    "QUIESCENT_FMT",
    "QUIESCENT_SIZE",
    # Helpers / decoders / errors
    "decode_kernel_ver",
    "read_header",
    "read_sections",
    "parse_event",
    "UnsupportedVersionError",
]


# --- File format constants ---
MAGIC = b"SCXI"
SUPPORTED_VERSION = 2  # v1 is intentionally unsupported (see PLAN.md §5/§11)

SECTION_TOPOLOGY = 0x0001
SECTION_PROCS    = 0x0002
SECTION_EVENTS   = 0x0003

# Event IDs live at 0x0100+ to stay structurally disjoint from section
# IDs (0x0001..0x0003). This is the v2 invariant; do not reintroduce
# event IDs in the section-ID range. See src/bpf/intf.h.
EVT_RUNNING   = 0x0100
EVT_STOPPING  = 0x0101
EVT_RUNNABLE  = 0x0102
EVT_QUIESCENT = 0x0103

EVT_NAMES = {
    EVT_RUNNING:   "RUNNING",
    EVT_STOPPING:  "STOPPING",
    EVT_RUNNABLE:  "RUNNABLE",
    EVT_QUIESCENT: "QUIESCENT",
}

# Exact per-type ABI payload size (full struct including 24-byte header).
# A candidate event TLV must match BOTH a known type AND its exact size;
# either alone admitted the v1 two-PID phantom-event bug.
EVT_SIZES = {
    EVT_RUNNING:   88,
    EVT_STOPPING:  88,
    EVT_RUNNABLE:  40,
    EVT_QUIESCENT: 32,
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


class UnsupportedVersionError(ValueError):
    """Raised when the .scxi file header carries an unsupported version."""


def read_header(data):
    """Parse the 64-byte file header. Rejects any version != SUPPORTED_VERSION."""
    if len(data) < 64:
        raise ValueError(f"File too small for header: {len(data)} bytes")
    if data[:4] != MAGIC:
        raise ValueError(f"Bad magic: {data[:4]!r} (expected {MAGIC!r})")

    version, header_size = struct.unpack_from("<HH", data, 4)
    if version != SUPPORTED_VERSION:
        raise UnsupportedVersionError(
            f"Unsupported SCXI version: file is v{version}, "
            f"this reader supports v{SUPPORTED_VERSION} only. "
            f"v1 traces are intentionally not supported (see PLAN.md §5/§11)."
        )
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
            # sec_len == 0 means "until next section header or EOF".
            # Events are TLVs: [event_type: u16][payload_len: u16][payload].
            #
            # Strict v2 detection: a candidate event MUST be a known event
            # type AND its payload_len MUST exactly match that type's ABI
            # size. The v1 reader admitted any payload size in {88,40,32,
            # 64}, which collided with a SECTION_PROCS payload of 40 bytes
            # (exactly two procs) and silently parsed it as an EVT_RUNNABLE.
            # In v2 event IDs (0x0100+) and section IDs (0x0001..0x0003) no
            # longer share numeric space, so the type check alone is now
            # decisive — but we still enforce the exact size as belt-and-
            # braces against any future ABI drift.
            while offset + 4 <= len(data):
                evt_type, payload_len = struct.unpack_from("<HH", data, offset)

                expected = EVT_SIZES.get(evt_type)
                if expected is None:
                    break  # unknown type → next section header reached
                if payload_len != expected:
                    break  # ABI size mismatch → treat as section boundary

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
