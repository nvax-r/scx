#!/usr/bin/env python3
"""
test_reader.py — regression tests for analysis/reader.py and the v2
trace format.

Pins the v2-only behavior of the in-tree reader plus the 2026-05-12
stack-sample additions:

  Case A: a synthetic v2 trace with two PIDs reconstructed from
          EVT_PROC_NEW (the legacy SECTION_PROCS slot 0x0002 is
          retired) parses cleanly. This is the shape that broke v1
          (`KNOWN_SIZES` admitted a 40-byte payload as an
          EVT_RUNNABLE phantom event).

  Case B: a v1-headered file is rejected fast with an explicit
          unsupported-version error. No partial decode allowed.

  Case C: a synthetic v2 trace exercising the new sections
          (SECTION_PROC_MAPS, SECTION_PROC_STACKS) and new event
          types (EVT_PROC_NEW, EVT_PROC_EXEC, EVT_SAMPLE) round-
          trips through the parser intact.

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
        payload += struct.pack("<HHHHIi", cpu, 0, 0, 2400, 1024, 0)
    sec_hdr = struct.pack("<HI", trace.SECTION_TOPOLOGY, len(payload))
    return sec_hdr + bytes(payload)


def _evt_hdr(pid: int, tgid: int, cpu: int, ts: int, evt_type: int) -> bytes:
    return struct.pack("<QIIIHH", ts, pid, tgid, cpu, evt_type, 0)


def _evt_runnable(pid: int, tgid: int, cpu: int, ts: int) -> bytes:
    """Build a single 40-byte EVT_RUNNABLE TLV (header included)."""
    full = bytearray(40)
    full[0:24] = _evt_hdr(pid, tgid, cpu, ts, trace.EVT_RUNNABLE)
    struct.pack_into("<QII", full, 24, 1_500_000, 0, 0)
    tlv = struct.pack("<HH", trace.EVT_RUNNABLE, len(full)) + bytes(full)
    return tlv


def _evt_proc_new(pid: int, tgid: int, ppid: int, comm: str, ts: int) -> bytes:
    full = bytearray(56)
    full[0:24] = _evt_hdr(pid, tgid, 0, ts, trace.EVT_PROC_NEW)
    comm_bytes = comm.encode("utf-8")[:16].ljust(16, b"\x00")
    struct.pack_into("<I16s", full, 24, ppid, comm_bytes)
    # 12 bytes of trailing pad already zeroed.
    tlv = struct.pack("<HH", trace.EVT_PROC_NEW, len(full)) + bytes(full)
    return tlv


def _evt_proc_exec(pid: int, tgid: int, ts: int,
                   comm: str = "") -> bytes:
    """Build an EVT_PROC_EXEC TLV.

    Default `comm=""` writes the current 40 B layout with an empty
    (all-zero) comm slot. Pass a real string to populate the
    post-exec comm refresh path. Pass `comm=None` to emit the
    pre-2026-05-12 legacy 24 B layout (header only, no comm) so the
    backward-compat parser branch is exercised.
    """
    if comm is None:
        full = _evt_hdr(pid, tgid, 0, ts, trace.EVT_PROC_EXEC)  # 24 B (legacy)
    else:
        body = bytearray(24 + 16)
        body[0:24] = _evt_hdr(pid, tgid, 0, ts, trace.EVT_PROC_EXEC)
        comm_bytes = comm.encode("utf-8")[:16].ljust(16, b"\x00")
        body[24:40] = comm_bytes
        full = bytes(body)
    tlv = struct.pack("<HH", trace.EVT_PROC_EXEC, len(full)) + bytes(full)
    return tlv


def _evt_sample(pid: int, tgid: int, cpu: int, ts: int, stack_id: int) -> bytes:
    """Build a 32 B on-disk EVT_SAMPLE TLV (post-recorder transform).

    The wire form (160 B with inline IPs) is the recorder's input;
    by the time bytes hit disk the recorder has already collapsed
    them via stack-id dedup. So our synthetic disk traces use the
    32 B form directly.
    """
    full = bytearray(32)
    full[0:24] = _evt_hdr(pid, tgid, cpu, ts, trace.EVT_SAMPLE)
    struct.pack_into("<iI", full, 24, stack_id, 0)
    tlv = struct.pack("<HH", trace.EVT_SAMPLE, len(full)) + bytes(full)
    return tlv


def _section_events(events: bytes) -> bytes:
    sec_hdr = struct.pack("<HI", trace.SECTION_EVENTS, 0)
    return sec_hdr + events


def _section_proc_maps(records: list) -> bytes:
    """Build a SECTION_PROC_MAPS body.

    Records may be either:
      - 2-tuples (pid, maps)            — flags=0
      - 3-tuples (pid, maps, flags_u16) — explicit flags slot
    where each map is (vm_start, vm_end, vm_pgoff, dso_inode, path_bytes).

    The 2-tuple form mirrors a pre-2026-05-12 v2 trace where the
    `flags` slot was zero-filled `pad`. The 3-tuple form exercises
    the post-update encoding.
    """
    body = bytearray()
    for record in records:
        if len(record) == 3:
            pid, maps, flags = record
        else:
            pid, maps = record
            flags = 0
        n_maps = len(maps)
        body += struct.pack("<IHH", pid, n_maps, flags)
        for vm_start, vm_end, vm_pgoff, dso_inode, path in maps:
            body += struct.pack("<QQQQ", vm_start, vm_end, vm_pgoff, dso_inode)
            body += struct.pack("<H", len(path))
            body += path
    sec_hdr = struct.pack("<HI", trace.SECTION_PROC_MAPS, len(body))
    return sec_hdr + bytes(body)


def _section_proc_stacks(records: list) -> bytes:
    """records: [(stack_id, [ip, ...]), ...]"""
    body = bytearray()
    for sid, ips in records:
        depth = len(ips)
        body += struct.pack("<IBBBB", sid, depth, 0, 0, 0)
        for ip in ips:
            body += struct.pack("<Q", ip)
    sec_hdr = struct.pack("<HI", trace.SECTION_PROC_STACKS, len(body))
    return sec_hdr + bytes(body)


def _write_temp_trace(blob: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".scxi")
    try:
        os.write(fd, blob)
    finally:
        os.close(fd)
    return path


class TestV2TwoPidTrace(unittest.TestCase):
    """Case A — the v1 phantom-event bug must not regress.

    SECTION_PROCS (0x0002) is gone; the proc table is now reconstructed
    from EVT_PROC_NEW. We synthesize two EVT_PROC_NEW + one
    EVT_RUNNABLE to mirror the v1 collision shape.
    """

    def test_two_pid_trace_parses_cleanly(self):
        evts = (
            _evt_proc_new(1234, 1234, 1, "alpha", 1_500_000_000)
            + _evt_proc_new(5678, 5678, 1, "beta",  1_500_000_001)
            + _evt_runnable(pid=1234, tgid=1234, cpu=0, ts=2_000_000_000)
        )
        blob = (
            _build_header(version=2)
            + _section_topology(nr_cpus=1)
            + _section_events(evts)
        )
        path = _write_temp_trace(blob)
        try:
            data = Path(path).read_bytes()
            hdr = trace.read_header(data)
            self.assertEqual(hdr["version"], 2)

            topology, events, proc_maps, proc_stacks, proc_flags, _raw = (
                trace.read_sections(data, hdr["header_size"])
            )

            # All three events round-trip.
            self.assertEqual(len(events), 3)
            evt_types = [e[0] for e in events]
            self.assertEqual(
                evt_types,
                [trace.EVT_PROC_NEW, trace.EVT_PROC_NEW, trace.EVT_RUNNABLE],
            )

            # Reconstructed proc table has two named entries.
            table = reader.build_proc_table(events)
            self.assertEqual(len(table), 2)
            self.assertEqual(table[1234]["comm"], "alpha")
            self.assertEqual(table[5678]["comm"], "beta")

            # No legacy proc-table section present in v2 traces.
            self.assertEqual(proc_maps, {})
            self.assertEqual(proc_stacks, {})
            self.assertEqual(proc_flags, {})

            # Topology survived.
            self.assertEqual(len(topology), 1)
        finally:
            os.unlink(path)


class TestV1Rejected(unittest.TestCase):
    """Case B — the v1 reader path is gone, and v1 files must be refused."""

    def test_v1_header_is_rejected_fast(self):
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
        blob = _build_header(version=1)
        path = _write_temp_trace(blob)
        try:
            data = Path(path).read_bytes()
            with self.assertRaises(ValueError):
                trace.read_header(data)
        finally:
            os.unlink(path)


class TestNewSectionsAndEvents(unittest.TestCase):
    """Case C — 2026-05-12 stack-sample additions.

    Round-trips a synthetic trace that exercises every new ABI piece:
    EVT_PROC_NEW, EVT_PROC_EXEC, EVT_SAMPLE (disk form),
    SECTION_PROC_MAPS, SECTION_PROC_STACKS.
    """

    def test_new_sections_round_trip(self):
        events = (
            _evt_proc_new(100, 100, 1, "worker",  1_500_000_000)
            + _evt_proc_exec(100, 100, 1_500_000_001)
            + _evt_sample(pid=100, tgid=100, cpu=0,
                          ts=1_500_000_002, stack_id=0)
            + _evt_sample(pid=100, tgid=100, cpu=0,
                          ts=1_500_000_003, stack_id=-14)  # walk failure
        )
        proc_maps = [
            (100, [
                (0x400000, 0x40b000, 0,           1234, b"/usr/bin/cat"),
                (0x600000, 0x601000, 0,           0,    b""),
            ]),
        ]
        proc_stacks = [
            (0, [0xdead0001, 0xdead0002, 0xdead0003]),
            (1, [0xbeef0001, 0xbeef0002]),
        ]
        blob = (
            _build_header(version=2)
            + _section_topology(nr_cpus=1)
            + _section_events(events)
            + _section_proc_maps(proc_maps)
            + _section_proc_stacks(proc_stacks)
        )
        path = _write_temp_trace(blob)
        try:
            data = Path(path).read_bytes()
            hdr = trace.read_header(data)
            topology, events_out, pm, ps, pf, _raw = trace.read_sections(
                data, hdr["header_size"]
            )

            # Events: PROC_NEW + PROC_EXEC + 2 × SAMPLE.
            self.assertEqual(len(events_out), 4)
            t = [e[0] for e in events_out]
            self.assertEqual(
                t,
                [trace.EVT_PROC_NEW, trace.EVT_PROC_EXEC,
                 trace.EVT_SAMPLE, trace.EVT_SAMPLE],
            )

            # Sample stack_ids decode correctly, including the
            # negative walk-failure form.
            sample0 = trace.parse_event(*events_out[2])
            sample1 = trace.parse_event(*events_out[3])
            self.assertEqual(sample0["stack_id"], 0)
            self.assertEqual(sample1["stack_id"], -14)

            # PROC_NEW carries the comm.
            pn = trace.parse_event(*events_out[0])
            self.assertEqual(pn["comm"], "worker")
            self.assertEqual(pn["ppid"], 1)

            # ProcMaps decoded with both file and anon entries.
            self.assertIn(100, pm)
            entries = pm[100]
            self.assertEqual(len(entries), 2)
            self.assertEqual(entries[0].vm_start, 0x400000)
            self.assertEqual(entries[0].path, b"/usr/bin/cat")
            self.assertEqual(entries[1].path, b"")  # anon

            # ProcStacks decoded.
            self.assertEqual(ps[0], [0xdead0001, 0xdead0002, 0xdead0003])
            self.assertEqual(ps[1], [0xbeef0001, 0xbeef0002])

            # ProcFlags carries an entry for every PID in proc_maps,
            # zero-valued when the writer left the slot blank
            # (pre-update v2 default; we used the 2-tuple form).
            self.assertEqual(pf, {100: 0})

            # Topology survived.
            self.assertEqual(len(topology), 1)
        finally:
            os.unlink(path)

    def test_proc_exec_increments_exec_count(self):
        """Pass-1 build_proc_table sees the EXEC bump.

        Empty-comm EVT_PROC_EXEC records (the test default) must NOT
        clobber the comm seeded by EVT_PROC_NEW. Only a non-empty
        post-exec comm refreshes the table — see the dedicated
        refresh test below.
        """
        events = (
            _evt_proc_new(200, 200, 1, "shell", 1_500_000_000)
            + _evt_proc_exec(200, 200, 1_500_000_001)
            + _evt_proc_exec(200, 200, 1_500_000_002)
        )
        blob = (
            _build_header(version=2)
            + _section_topology(nr_cpus=1)
            + _section_events(events)
        )
        path = _write_temp_trace(blob)
        try:
            data = Path(path).read_bytes()
            hdr = trace.read_header(data)
            _, evts, _, _, _, _ = trace.read_sections(data, hdr["header_size"])
            table = reader.build_proc_table(evts)
            self.assertEqual(table[200]["comm"], "shell")
            self.assertEqual(table[200]["execs"], 2)
        finally:
            os.unlink(path)

    def test_proc_exec_refreshes_comm(self):
        """Post-exec comm in EVT_PROC_EXEC overrides the fork-time comm.

        This is the spawn-mode bug fix: `record -- nvbandwidth ...`
        forks a child whose comm at sched_fork time is still the
        recorder's "scx_invariant" (inherited across clone). The
        EVT_PROC_EXEC fired post-execve must rewrite the analyzer's
        per-PID comm to "nvbandwidth" so the wakeup graph renders
        the workload under its real name. Without this refresh the
        node label stays at the parent's pre-exec comm forever.

        Two execs in a row exercise multi-exec chains (e.g. a shell
        running `exec ls`) — the latest post-exec comm wins.
        """
        events = (
            _evt_proc_new(300, 300, 1, "scx_invariant", 1_500_000_000)
            + _evt_proc_exec(300, 300, 1_500_000_001, comm="sh")
            + _evt_proc_exec(300, 300, 1_500_000_002, comm="nvbandwidth")
        )
        blob = (
            _build_header(version=2)
            + _section_topology(nr_cpus=1)
            + _section_events(events)
        )
        path = _write_temp_trace(blob)
        try:
            data = Path(path).read_bytes()
            hdr = trace.read_header(data)
            _, evts, _, _, _, _ = trace.read_sections(data, hdr["header_size"])

            # parse_event surfaces the post-exec comm on the EVT
            # itself, so analyzers that bypass build_proc_table can
            # still see the refresh.
            execs = [trace.parse_event(t, p)
                     for t, p in evts if t == trace.EVT_PROC_EXEC]
            self.assertEqual([e["comm"] for e in execs], ["sh", "nvbandwidth"])

            table = reader.build_proc_table(evts)
            # Latest post-exec comm wins; exec counter sees both.
            self.assertEqual(table[300]["comm"], "nvbandwidth")
            self.assertEqual(table[300]["execs"], 2)
        finally:
            os.unlink(path)

    def test_legacy_proc_exec_size_still_parses(self):
        """Pre-2026-05-12 v2 traces (24 B EVT_PROC_EXEC) keep working.

        Old EVT_PROC_EXEC carried no comm payload. The strict-size
        check in `read_sections` admits both 24 B (legacy) and 40 B
        (current). build_proc_table for a 24 B record bumps the
        exec counter but leaves comm untouched — the correct
        historical reading.
        """
        events = (
            _evt_proc_new(400, 400, 1, "original", 1_500_000_000)
            + _evt_proc_exec(400, 400, 1_500_000_001, comm=None)
        )
        blob = (
            _build_header(version=2)
            + _section_topology(nr_cpus=1)
            + _section_events(events)
        )
        path = _write_temp_trace(blob)
        try:
            data = Path(path).read_bytes()
            hdr = trace.read_header(data)
            _, evts, _, _, _, _ = trace.read_sections(data, hdr["header_size"])

            # Both events accepted by the size validator.
            self.assertEqual(
                [t for t, _ in evts],
                [trace.EVT_PROC_NEW, trace.EVT_PROC_EXEC],
            )
            # Legacy EVT_PROC_EXEC body is 0 B; parse_event omits
            # the `comm` key for these records.
            exec_payload = next(p for t, p in evts if t == trace.EVT_PROC_EXEC)
            self.assertEqual(len(exec_payload), 24)
            self.assertNotIn("comm", trace.parse_event(trace.EVT_PROC_EXEC,
                                                       exec_payload))

            table = reader.build_proc_table(evts)
            self.assertEqual(table[400]["comm"], "original")
            self.assertEqual(table[400]["execs"], 1)
        finally:
            os.unlink(path)

    def test_proc_maps_flags_round_trip(self):
        """Per-PID flags slot decodes for the new (post-2026-05-12) writer.

        Synthesizes one PID with every flag bit set, one with only
        INHERITED_FROM_PARENT (the dominant case for sub-millisecond
        forks), and one with the historical zero-pad form.
        """
        all_flags = (trace.PROC_FLAG_NO_MAPS
                     | trace.PROC_FLAG_PARTIAL_IDENTITY
                     | trace.PROC_FLAG_INHERITED_FROM_PARENT)
        records = [
            (10, [], 0),
            (20, [(0x400000, 0x401000, 0, 1, b"/bin/sh")],
             trace.PROC_FLAG_INHERITED_FROM_PARENT),
            (30, [], all_flags),
        ]
        blob = (
            _build_header(version=2)
            + _section_topology(nr_cpus=1)
            + _section_events(b"")
            + _section_proc_maps(records)
        )
        path = _write_temp_trace(blob)
        try:
            data = Path(path).read_bytes()
            hdr = trace.read_header(data)
            _, _, pm, _, pf, _ = trace.read_sections(data, hdr["header_size"])

            self.assertEqual(set(pm.keys()), {10, 20, 30})
            self.assertEqual(pf[10], 0)
            self.assertEqual(pf[20], trace.PROC_FLAG_INHERITED_FROM_PARENT)
            self.assertEqual(pf[30], all_flags)
            self.assertEqual(len(pm[20]), 1)
            self.assertEqual(pm[20][0].path, b"/bin/sh")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
