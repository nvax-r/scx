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
`read_sections`, `parse_event`, `MapEntry`, and
`UnsupportedVersionError`.

`reader.py`, `report.py`, and `symbolizer.py` all consume this module
so the decoder lives in exactly one place.

Stdlib only — `struct`, `collections`.
"""

import struct
from collections import namedtuple


__all__ = [
    # File / section / event identity
    "MAGIC",
    "SUPPORTED_VERSION",
    "SECTION_TOPOLOGY",
    "SECTION_EVENTS",
    "SECTION_PROC_MAPS",
    "SECTION_PROC_STACKS",
    "EVT_RUNNING",
    "EVT_STOPPING",
    "EVT_RUNNABLE",
    "EVT_QUIESCENT",
    "EVT_PROC_NEW",
    "EVT_PROC_EXEC",
    "EVT_SAMPLE",
    "EVT_NAMES",
    "EVT_SIZES",
    # Event-header flags
    "FLAG_MIGRATED",
    "FLAG_SYNC_WAKEUP",
    "FLAG_VOLUNTARY",
    # Per-PID flags in SECTION_PROC_MAPS
    "PROC_FLAG_NO_MAPS",
    "PROC_FLAG_PARTIAL_IDENTITY",
    "PROC_FLAG_INHERITED_FROM_PARENT",
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
    "PROC_NEW_FMT",
    "PROC_NEW_SIZE",
    "PROC_EXEC_FMT",
    "PROC_EXEC_SIZE",
    "PROC_EXEC_LEGACY_SIZE",
    "SAMPLE_FMT",
    "SAMPLE_SIZE",
    "STACK_DEPTH_MAX",
    # Helpers / decoders / errors
    "decode_kernel_ver",
    "read_header",
    "read_sections",
    "parse_event",
    "MapEntry",
    "UnsupportedVersionError",
]


# --- File format constants ---
MAGIC = b"SCXI"
SUPPORTED_VERSION = 2  # v1 is intentionally unsupported (see PLAN.md §5/§11)

SECTION_TOPOLOGY    = 0x0001
# 0x0002 (SECTION_PROCS) is permanently retired — the pid → comm
# mapping is reconstructed from the EVT_PROC_NEW event stream now.
# Do not re-use the slot; see work/changelog.md 2026-05-12.
SECTION_EVENTS      = 0x0003
SECTION_PROC_MAPS   = 0x0004
SECTION_PROC_STACKS = 0x0005

# Event IDs live at 0x0100+ to stay structurally disjoint from section
# IDs (0x0001..0x00FF). This is the v2 invariant; do not reintroduce
# event IDs in the section-ID range. See src/bpf/intf.h.
EVT_RUNNING   = 0x0100
EVT_STOPPING  = 0x0101
EVT_RUNNABLE  = 0x0102
EVT_QUIESCENT = 0x0103
EVT_PROC_NEW  = 0x0104
EVT_PROC_EXEC = 0x0105
EVT_SAMPLE    = 0x0106

EVT_NAMES = {
    EVT_RUNNING:   "RUNNING",
    EVT_STOPPING:  "STOPPING",
    EVT_RUNNABLE:  "RUNNABLE",
    EVT_QUIESCENT: "QUIESCENT",
    EVT_PROC_NEW:  "PROC_NEW",
    EVT_PROC_EXEC: "PROC_EXEC",
    EVT_SAMPLE:    "SAMPLE",
}

# Exact per-type ABI payload size (full struct including 24-byte header).
# A candidate event TLV must match BOTH a known type AND a size from
# this table; either alone admitted the v1 two-PID phantom-event bug.
#
# Values are either an int (single accepted size) or a frozenset (one
# of several accepted sizes — used for backward-compat-friendly ABI
# growth). The size-mismatch check at the call site handles both.
#
# EVT_SAMPLE on disk is 32 B; the BPF→userspace wire form is fatter
# (carries the inline IP[16]) but the recorder transforms it before
# disk write — see src/output.rs::write_sample_event.
#
# EVT_PROC_EXEC accepts {24, 40}: 24 B is the pre-2026-05-12 layout
# (header only, no comm), 40 B is the current layout that carries
# the post-exec in-kernel `task->comm`. Old v2 traces parse cleanly
# under "no comm refresh" semantics. See work/changelog.md
# 2026-05-12 (post-exec comm refresh).
EVT_SIZES = {
    EVT_RUNNING:   88,
    EVT_STOPPING:  88,
    EVT_RUNNABLE:  40,
    EVT_QUIESCENT: 32,
    EVT_PROC_NEW:  56,
    EVT_PROC_EXEC: frozenset({24, 40}),
    EVT_SAMPLE:    32,
}

FLAG_MIGRATED    = 1 << 0
FLAG_SYNC_WAKEUP = 1 << 1
FLAG_VOLUNTARY   = 1 << 2

# --- Per-PID flags in the SECTION_PROC_MAPS record ---
#
# Encoded into the second u16 of every per-PID record (the slot was
# zero-filled `pad` in v2 traces written before 2026-05-12; old traces
# decode as "all flags clear", which is the correct historical
# interpretation). Bit assignments are stable; mirror src/output.rs
# `PROC_FLAG_*` constants. Add new flags by claiming higher bits.
#
# - NO_MAPS: snapshot_proc found neither /proc/<pid> nor /proc/<ppid>.
# - PARTIAL_IDENTITY: a scheduling event arrived for a PID before its
#   EVT_PROC_NEW (the proc-new ringbuf record was dropped); the
#   recorder filled in identity inline as a fallback.
# - INHERITED_FROM_PARENT: /proc/<pid> was gone at snapshot time
#   (sub-millisecond ephemeral fork — emit-then-exit faster than the
#   ringbuf consumer drained), so we used /proc/<ppid>/maps as a
#   stand-in. This is the dominant outcome for short-lived tasks
#   under realistic fork-heavy workloads.
PROC_FLAG_NO_MAPS               = 1 << 0
PROC_FLAG_PARTIAL_IDENTITY      = 1 << 1
PROC_FLAG_INHERITED_FROM_PARENT = 1 << 2

ARCH_NAMES = {0: "unknown", 1: "aarch64", 2: "x86_64"}

# Mirror of STACK_DEPTH_MAX in src/bpf/intf.h. Used only for sanity
# checks in the analyzer; the on-disk depth field is the source of
# truth for actual frame count.
STACK_DEPTH_MAX = 16

# --- Struct formats (aarch64 LE) ---
# Common event header: timestamp_ns(u64) pid(u32) tgid(u32) cpu(u32) event_type(u16) flags(u16)
HDR_FMT = "<QIIIHH"  # 24 bytes
HDR_SIZE = struct.calcsize(HDR_FMT)

# evt_running payload after header (64 bytes):
#   runq_wait_ns(u64) waker_pid(u32) waker_tgid(u32) waker_flags(u16) cpu_perf(u16)
#   prev_cpu(i32) wake_flags(u64) pmc_inst(u64) pmc_cyc(u64) pmc_l2(u64) pmc_stall(u64)
#
# `cpu_perf` and `pmc_*` are RESERVED-ZERO in the current producer
# (see src/bpf/intf.h). The format string and size are frozen for v2
# ABI stability so older v2 traces and the parser stay aligned;
# `parse_event()` still decodes them so consumers can introspect the
# field layout if they want, but normal summaries should ignore them.
RUNNING_FMT = "<QIIHHiQQQQQ"
RUNNING_SIZE = struct.calcsize(RUNNING_FMT)

# evt_stopping payload after header (64 bytes):
#   runtime_ns(u64) pmc_inst(u64) pmc_cyc(u64) pmc_l2(u64) pmc_stall(u64)
#   slice_consumed(u64) slice_allocated(u64) voluntary(u8) pad(7 bytes)
#
# `pmc_*` are RESERVED-ZERO in the current producer (see
# src/bpf/intf.h). Same v2 stability rationale as RUNNING_FMT.
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

# evt_proc_new payload after header (32 bytes):
#   ppid(u32) comm(16 bytes) pad(12 bytes)
PROC_NEW_FMT = "<I16s12x"
PROC_NEW_SIZE = struct.calcsize(PROC_NEW_FMT)

# evt_proc_exec payload after header (16 bytes):
#   comm(16 bytes)
#
# Layout history:
#   * pre-2026-05-12: 0 B payload (header only). EVT_PROC_EXEC was a
#     bare flag carrying just pid in the header; the recorder reacted
#     by re-reading /proc/<pid>/{maps, cmdline}.
#   * 2026-05-12+   : 16 B payload carrying the post-exec
#     `task->comm` so the analyzer can refresh the per-PID name. See
#     EVT_SIZES note above. PROC_EXEC_LEGACY_SIZE is exported for
#     callers that need to distinguish the two on the wire.
PROC_EXEC_FMT = "<16s"
PROC_EXEC_SIZE = struct.calcsize(PROC_EXEC_FMT)
PROC_EXEC_LEGACY_SIZE = 0  # body size of the pre-2026-05-12 layout

# evt_sample (DISK form) payload after header (8 bytes):
#   stack_id(s32) pad(u32)
SAMPLE_FMT = "<iI"
SAMPLE_SIZE = struct.calcsize(SAMPLE_FMT)


# Lightweight container for one /proc/<pid>/maps entry decoded from
# the ProcMaps section. Used by the symbolizer and the report's
# stack-profile section; `path` is bytes (filesystem encoding).
MapEntry = namedtuple("MapEntry",
                      ["vm_start", "vm_end", "vm_pgoff", "dso_inode", "path"])


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


def _parse_proc_maps_section(data, offset, end):
    """Decode a SECTION_PROC_MAPS body into per-PID maps + flags.

    Layout (per src/output.rs::write_proc_maps_section):
      per-PID record:
        [pid: u32][n_maps: u16][flags: u16]
        n_maps × {
          [vm_start: u64][vm_end: u64][vm_pgoff: u64]
          [dso_inode: u64][path_len: u16][path: bytes]
        }

    The `flags` slot was a zero-filled `pad: u16` in v2 traces written
    before 2026-05-12. Old traces decode as flags=0 ("all clear"),
    which is the correct historical interpretation. Bit assignments
    are documented at PROC_FLAG_* in this module.

    Returns `(maps, flags, offset)` where:
      - maps: {pid: int -> list[MapEntry]}
      - flags: {pid: int -> int}     (0 if the record had no flags set;
        the dict carries an entry for every PID in `maps` so callers
        can use `flags.get(pid, 0)` defensively without KeyError).
    """
    maps_out: dict = {}
    flags_out: dict = {}
    while offset + 8 <= end:
        pid, n_maps, flags = struct.unpack_from("<IHH", data, offset)
        offset += 8
        entries = []
        for _ in range(n_maps):
            if offset + 32 + 2 > end:
                break
            vm_start, vm_end, vm_pgoff, dso_inode = struct.unpack_from(
                "<QQQQ", data, offset
            )
            offset += 32
            path_len, = struct.unpack_from("<H", data, offset)
            offset += 2
            if offset + path_len > end:
                break
            path = bytes(data[offset:offset + path_len])
            offset += path_len
            entries.append(MapEntry(vm_start, vm_end, vm_pgoff, dso_inode, path))
        maps_out[pid] = entries
        flags_out[pid] = flags
    return maps_out, flags_out, offset


def _parse_proc_stacks_section(data, offset, end):
    """Decode a SECTION_PROC_STACKS body into {stack_id: [ip, ...]}.

    Layout (per src/output.rs::write_proc_stacks_section):
      per-stack record:
        [stack_id: u32][depth: u8][pad: u8 × 3]
        depth × [ip: u64]
    """
    out: dict = {}
    while offset + 8 <= end:
        stack_id, depth, _p0, _p1, _p2 = struct.unpack_from(
            "<IBBBB", data, offset
        )
        offset += 8
        ips = []
        for _ in range(depth):
            if offset + 8 > end:
                break
            ip, = struct.unpack_from("<Q", data, offset)
            offset += 8
            ips.append(ip)
        out[stack_id] = ips
    return out, offset


def read_sections(data, offset):
    """Parse all sections after the header.

    Returns a 6-tuple:
        (topology, events, proc_maps, proc_stacks, proc_flags, raw_section_log)
    where:
      - topology:    list[dict] of CPU records (cpu_id, llc_id, ...)
      - events:      list[(evt_type, payload_bytes)]
      - proc_maps:   dict[pid: int -> list[MapEntry]]
      - proc_stacks: dict[stack_id: int -> list[ip: int]]
      - proc_flags:  dict[pid: int -> int]
        (per-PID flag bits — see PROC_FLAG_* constants. Carries an
        entry for every PID in `proc_maps`; missing PIDs imply 0.)
      - raw_section_log: list[(sec_type, sec_len)] in the order seen
        (debugging aid; consumers can ignore).

    The legacy SECTION_PROCS (0x0002) parser path is gone. A trace
    file produced by an older recorder that still emits 0x0002 will
    be rejected at header parse via UnsupportedVersionError if it's
    v1; v2 files never carried 0x0002 so this is safe.

    `proc_flags` was added in the 2026-05-12 update to surface the
    parent-fallback / partial-identity / no-maps states the recorder
    now tracks. Pre-update v2 traces decode as proc_flags={pid: 0
    for every pid} (the slot was zero-filled `pad`), which is the
    correct historical reading.
    """
    topology = []
    events = []
    proc_maps: dict = {}
    proc_stacks: dict = {}
    proc_flags: dict = {}
    raw_log: list = []

    while offset < len(data):
        if offset + 6 > len(data):
            break
        sec_type, sec_len = struct.unpack_from("<HI", data, offset)
        offset += 6
        raw_log.append((sec_type, sec_len))

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
            # Strict v2 detection: a candidate event MUST be a known
            # event type AND its payload_len MUST exactly match that
            # type's ABI size. The v1 reader admitted any payload size
            # in {88,40,32,64}, which collided with a SECTION_PROCS
            # payload of 40 bytes (exactly two procs) and silently
            # parsed it as an EVT_RUNNABLE. In v2 event IDs (0x0100+)
            # and section IDs (0x0001..0x00FF) no longer share numeric
            # space, so the type check alone is now decisive — but we
            # still enforce the exact size as belt-and-braces against
            # any future ABI drift.
            while offset + 4 <= len(data):
                evt_type, payload_len = struct.unpack_from("<HH", data, offset)

                expected = EVT_SIZES.get(evt_type)
                if expected is None:
                    break  # unknown type → next section header reached
                # `expected` is either an int (single accepted size) or
                # a frozenset (one of several — used by EVT_PROC_EXEC
                # to admit both pre- and post-2026-05-12 layouts).
                if isinstance(expected, (set, frozenset)):
                    if payload_len not in expected:
                        break
                elif payload_len != expected:
                    break

                offset += 4
                if offset + payload_len > len(data):
                    break

                payload = data[offset : offset + payload_len]
                events.append((evt_type, payload))
                offset += payload_len

        elif sec_type == SECTION_PROC_MAPS:
            end = offset + sec_len
            proc_maps, proc_flags, offset = _parse_proc_maps_section(
                data, offset, end
            )
            offset = end  # be defensive against partial decode

        elif sec_type == SECTION_PROC_STACKS:
            end = offset + sec_len
            proc_stacks, offset = _parse_proc_stacks_section(data, offset, end)
            offset = end

        else:
            # Unknown section — skip if we can
            if sec_len > 0:
                offset += sec_len
            else:
                break

    return topology, events, proc_maps, proc_stacks, proc_flags, raw_log


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

    elif evt_type == EVT_PROC_NEW and len(body) >= PROC_NEW_SIZE:
        ppid, comm = struct.unpack_from(PROC_NEW_FMT, body, 0)
        result.update({
            "ppid": ppid,
            "comm": comm.split(b"\x00", 1)[0].decode("utf-8", errors="replace"),
        })

    elif evt_type == EVT_PROC_EXEC:
        # Body is 0 B in pre-2026-05-12 traces and 16 B (comm) in
        # current traces. Decode comm when present; old traces just
        # carry the bare header and we leave `comm` out of the dict.
        # Downstream consumers (build_proc_table) treat a missing
        # `comm` key as "no refresh" — see analysis/report.py.
        if len(body) >= PROC_EXEC_SIZE:
            comm, = struct.unpack_from(PROC_EXEC_FMT, body, 0)
            result["comm"] = comm.split(b"\x00", 1)[0].decode(
                "utf-8", errors="replace"
            )

    elif evt_type == EVT_SAMPLE and len(body) >= SAMPLE_SIZE:
        fields = struct.unpack_from(SAMPLE_FMT, body, 0)
        result.update({
            "stack_id": fields[0],
        })

    return result
