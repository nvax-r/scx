#!/usr/bin/env python3
"""
test_reader.py — regression tests for analysis/reader.py.

Pins the v2-only behavior of the in-tree reader:

  Case A: a synthetic v2 trace with exactly two PIDs in the process
          table (sec_len = 40 bytes) parses cleanly. This is the
          shape that broke v1 — `KNOWN_SIZES` admitted a 40-byte
          payload as an EVT_RUNNABLE phantom event.

  Case B: a v1-headered file is rejected fast with an explicit
          unsupported-version error. No partial decode is allowed.

Run:
    python3 scheds/rust/scx_invariant/analysis/test_reader.py

Stdlib only — `unittest`, `tempfile`, `struct`, `pathlib`.
"""

import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import trace  # noqa: E402
import reader  # noqa: E402, F401  # import-only smoke test that reader.py still loads


# Field widths the synthesizer needs to know about. Kept local on
# purpose so this test file is self-contained and breaks loudly if
# anyone changes the on-disk layout without updating the test.
HEADER_SIZE = 64
TOPO_ENTRY_SIZE = 16
PROC_ENTRY_SIZE = 20
EVT_HDR_SIZE = 24


def _build_header(version: int, ts_start: int = 1_000_000_000) -> bytes:
    """Build a 64-byte SCXI file header with the requested version."""
    buf = bytearray(HEADER_SIZE)
    buf[0:4] = b"SCXI"
    struct.pack_into("<HH", buf, 4, version, HEADER_SIZE)  # version, header_size
    struct.pack_into("<I", buf, 8, 0)                       # flags
    struct.pack_into("<Q", buf, 12, ts_start)               # ts_start
    struct.pack_into("<Q", buf, 20, ts_start + 1_000_000)   # ts_end
    hostname = b"testhost"
    buf[28:28 + len(hostname)] = hostname                   # 28..56 (rest zero)
    struct.pack_into("<I", buf, 56, (6 << 16) | (17 << 8) | 0)  # kernel 6.17.0
    struct.pack_into("<HH", buf, 60, 1, 1)                  # arch=aarch64, nr_cpus=1
    return bytes(buf)


def _section_topology(nr_cpus: int = 1) -> bytes:
    """Section header + nr_cpus * 16-byte CPU entries."""
    payload = bytearray()
    for cpu in range(nr_cpus):
        # cpu_id, llc_id, numa_id, max_freq_mhz, capacity, _pad
        payload += struct.pack("<HHHHIi", cpu, 0, 0, 2400, 1024, 0)
    sec_hdr = struct.pack("<HI", trace.SECTION_TOPOLOGY, len(payload))
    return sec_hdr + bytes(payload)


def _evt_runnable(pid: int, tgid: int, cpu: int, ts: int) -> bytes:
    """Build a single 40-byte EVT_RUNNABLE TLV (header included)."""
    full = bytearray(40)
    # common header @ 0..24
    struct.pack_into("<QIII HH", full, 0,
                     ts, pid, tgid, cpu, trace.EVT_RUNNABLE, 0)
    # payload @ 24..40: sleep_duration_ns(u64), enq_flags(u32), pad(u32)
    struct.pack_into("<QII", full, 24, 1_500_000, 0, 0)
    tlv = struct.pack("<HH", trace.EVT_RUNNABLE, len(full)) + bytes(full)
    return tlv


def _section_events(events: bytes) -> bytes:
    # SECTION_EVENTS uses sec_len=0 in the producer (see output.rs); the
    # reader walks TLVs until it hits a non-event type or EOF. Mirror
    # that here so the test exercises the production code path.
    sec_hdr = struct.pack("<HI", trace.SECTION_EVENTS, 0)
    return sec_hdr + events


def _section_procs(entries: list[tuple[int, str]]) -> bytes:
    """Section header + 20-byte (pid, comm[16]) entries."""
    payload = bytearray()
    for pid, comm in entries:
        comm_b = comm.encode("utf-8")[:16].ljust(16, b"\x00")
        payload += struct.pack("<I", pid) + comm_b
    sec_hdr = struct.pack("<HI", trace.SECTION_PROCS, len(payload))
    return sec_hdr + bytes(payload)


def _write_temp_trace(blob: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".scxi")
    try:
        os.write(fd, blob)
    finally:
        os.close(fd)
    return path


class TestV2TwoPidTrace(unittest.TestCase):
    """Case A — the v1 phantom-event bug must not regress."""

    def test_two_pid_trace_parses_cleanly(self):
        # Compose: header(v2) + topology + events(1 EVT_RUNNABLE) + procs(2 entries)
        # The procs section payload is exactly 2 * 20 = 40 bytes — the
        # collision shape that broke v1.
        evts = _evt_runnable(pid=1234, tgid=1234, cpu=0, ts=2_000_000_000)
        blob = (
            _build_header(version=2)
            + _section_topology(nr_cpus=1)
            + _section_events(evts)
            + _section_procs([(1234, "alpha"), (5678, "beta")])
        )
        path = _write_temp_trace(blob)
        try:
            data = Path(path).read_bytes()
            hdr = trace.read_header(data)
            self.assertEqual(hdr["version"], 2)

            topology, events, procs = trace.read_sections(data, hdr["header_size"])

            # Process table parses to exactly two entries.
            self.assertEqual(len(procs), 2, f"expected 2 procs, got {procs!r}")
            self.assertEqual(procs[1234], "alpha")
            self.assertEqual(procs[5678], "beta")

            # Exactly the one event we wrote — no phantom from the procs
            # section being misread as an EVT_RUNNABLE.
            self.assertEqual(len(events), 1, f"phantom event detected: {events!r}")
            evt_type, _payload = events[0]
            self.assertEqual(evt_type, trace.EVT_RUNNABLE)

            # Topology survived as well.
            self.assertEqual(len(topology), 1)
        finally:
            os.unlink(path)


class TestV1Rejected(unittest.TestCase):
    """Case B — the v1 reader path is gone, and v1 files must be refused."""

    def test_v1_header_is_rejected_fast(self):
        # A minimally valid v1 header is enough — read_header should
        # bail before any section walking happens.
        blob = _build_header(version=1) + _section_topology(nr_cpus=1)
        path = _write_temp_trace(blob)
        try:
            data = Path(path).read_bytes()
            with self.assertRaises(trace.UnsupportedVersionError) as cm:
                trace.read_header(data)
            msg = str(cm.exception)
            self.assertIn("v1", msg)
            self.assertIn("v2", msg)
        finally:
            os.unlink(path)

    def test_v1_rejection_is_a_valueerror_subclass(self):
        # UnsupportedVersionError must remain catchable as ValueError so
        # generic callers don't need to know about the new exception.
        blob = _build_header(version=1)
        path = _write_temp_trace(blob)
        try:
            data = Path(path).read_bytes()
            with self.assertRaises(ValueError):
                trace.read_header(data)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
