#!/usr/bin/env python3
"""
test_symbolizer.py — unit tests for analysis/symbolizer.py.

Coverage matches docs/superpowers/specs/2026-05-12-stack-sample-thread-annotation-design.md §9:

  - Mapping lookup correctness (boundary IPs, contiguous mappings,
    anon mappings).
  - addr2line caching: the same DSO is used for many resolves but
    only spawned once.
  - Graceful fallback when the binary is missing on the analyzer's
    filesystem.
  - Graceful fallback for stripped binaries (addr2line returns "??").

Run:
    python3 scheds/rust/scx_invariant/analysis/test_symbolizer.py

Stdlib only (`unittest`, `subprocess`, `tempfile`, `pathlib`,
`shutil`).  No external test fixtures committed; addr2line is
exercised against tiny binaries built at test time when the host
toolchain is present, and skipped otherwise (annotated as such).
"""

import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from trace import MapEntry  # noqa: E402
import symbolizer  # noqa: E402


def _have(prog):
    return shutil.which(prog) is not None


class TestMappingLookup(unittest.TestCase):
    """Boundary-IP and anon-mapping cases for the lookup-only path."""

    def setUp(self):
        # Two contiguous executable mappings + one anon at higher addr.
        self.maps = {
            42: [
                MapEntry(0x400000, 0x40b000, 0,    1234, b"/missing/binary"),
                MapEntry(0x40b000, 0x420000, 0xb000, 1234, b"/missing/binary"),
                MapEntry(0x500000, 0x501000, 0,    0,    b""),
            ]
        }
        self.sym = symbolizer.Symbolizer(self.maps)

    def tearDown(self):
        self.sym.close()

    def test_ip_in_first_mapping(self):
        result = self.sym.resolve(42, 0x400010)
        # Binary missing → fallback to "binary+0x<offset>".
        # offset = (0x400010 - 0x400000) + 0 = 0x10
        self.assertIn("+0x10", result)

    def test_ip_at_lower_boundary_is_inclusive(self):
        result = self.sym.resolve(42, 0x400000)
        self.assertIn("+0x0", result)

    def test_ip_at_upper_boundary_lands_in_next_mapping(self):
        # 0x40b000 is exactly vm_end of mapping 0 / vm_start of mapping 1.
        # Half-open semantics: it belongs to mapping 1.
        result = self.sym.resolve(42, 0x40b000)
        # offset in mapping 1 = (0x40b000 - 0x40b000) + 0xb000 = 0xb000
        self.assertIn("+0xb000", result)

    def test_ip_above_all_mappings_unmapped(self):
        result = self.sym.resolve(42, 0x999999)
        self.assertIn("[unmapped]", result)

    def test_ip_below_all_mappings_unmapped(self):
        result = self.sym.resolve(42, 0x100)
        self.assertIn("[unmapped]", result)

    def test_anonymous_mapping_renders_as_anon(self):
        result = self.sym.resolve(42, 0x500080)
        self.assertTrue(result.startswith("[anon]+0x"),
                        f"expected [anon]+0x… got {result!r}")

    def test_unknown_pid_renders_as_unmapped(self):
        result = self.sym.resolve(9999, 0x400000)
        self.assertIn("[unmapped]", result)

    def test_resolve_is_cached(self):
        # Two resolves of the same (pid, ip) must return the same string
        # without recomputation. We can't directly observe cache hits
        # from outside; we just assert the contract holds.
        a = self.sym.resolve(42, 0x400010)
        b = self.sym.resolve(42, 0x400010)
        self.assertEqual(a, b)


@unittest.skipUnless(_have("cc") and _have("addr2line"),
                     "needs a C compiler and addr2line on PATH")
class TestAddr2lineLive(unittest.TestCase):
    """Spawn a real addr2line against a tiny binary.

    Skipped on hosts without the toolchain. The binary is built once
    per test method (cheap; <100 ms on any modern host).
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="scxi_symbolizer_test_")
        self.src = Path(self.tmp) / "tiny.c"
        self.bin = Path(self.tmp) / "tiny"
        self.src.write_text(textwrap.dedent("""
            int helper(int x) { return x * 2; }
            int main(int argc, char **argv) {
                (void)argc; (void)argv;
                return helper(21);
            }
        """))
        # -g for DWARF debug info; -no-pie so the symbols sit at fixed
        # virtual addresses we can predict via objdump. -O0 keeps the
        # functions un-inlined.
        subprocess.run(
            ["cc", "-g", "-O0", "-no-pie", "-o", str(self.bin), str(self.src)],
            check=True,
            stderr=subprocess.PIPE,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _addr_of(self, name):
        # nm output: `<addr> T <name>`; -no-pie binaries have absolute
        # addresses so nm prints them directly.
        out = subprocess.check_output(["nm", "--defined-only", str(self.bin)])
        for line in out.decode().splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[2] == name:
                return int(parts[0], 16)
        raise RuntimeError(f"symbol {name!r} not found in {self.bin}")

    def test_resolves_function_name(self):
        addr_helper = self._addr_of("helper")
        # Construct a single mapping that covers the binary's text segment.
        # We pin vm_start at 0 and vm_pgoff such that
        # file_offset = (ip - 0) + vm_pgoff = addr_helper.
        maps = {
            1: [MapEntry(
                vm_start=0,
                vm_end=0xffff_ffff_ffff,
                vm_pgoff=0,
                dso_inode=0,
                path=str(self.bin).encode("utf-8"),
            )]
        }
        with symbolizer.Symbolizer(maps) as sym:
            name = sym.resolve(1, addr_helper)
        self.assertEqual(name, "helper")

    def test_caching_does_not_respawn(self):
        addr_helper = self._addr_of("helper")
        maps = {
            1: [MapEntry(
                vm_start=0,
                vm_end=0xffff_ffff_ffff,
                vm_pgoff=0,
                dso_inode=0,
                path=str(self.bin).encode("utf-8"),
            )]
        }
        with symbolizer.Symbolizer(maps) as sym:
            sym.resolve(1, addr_helper)
            # Internal: only one Popen handle exists for this DSO.
            self.assertEqual(len(sym._addr2line), 1)
            for _ in range(50):
                sym.resolve(1, addr_helper)
            # Still one process, not 51.
            self.assertEqual(len(sym._addr2line), 1)

    def test_stripped_binary_falls_back_to_offset(self):
        # Make a stripped copy of the binary so addr2line returns "??".
        stripped = Path(self.tmp) / "tiny.stripped"
        shutil.copy(self.bin, stripped)
        subprocess.run(["strip", str(stripped)], check=True,
                       stderr=subprocess.PIPE)
        addr_helper = self._addr_of("helper")
        maps = {
            1: [MapEntry(
                vm_start=0,
                vm_end=0xffff_ffff_ffff,
                vm_pgoff=0,
                dso_inode=0,
                path=str(stripped).encode("utf-8"),
            )]
        }
        with symbolizer.Symbolizer(maps) as sym:
            name = sym.resolve(1, addr_helper)
        # Stripped binary → addr2line emits "??" → fallback rendering.
        self.assertTrue(
            name.startswith("tiny.stripped+0x"),
            f"expected basename+0x… fallback, got {name!r}",
        )


class TestMissingBinaryFallback(unittest.TestCase):
    """Binary path doesn't exist on the analyzer's filesystem."""

    def test_missing_binary_renders_basename_plus_offset(self):
        maps = {
            7: [MapEntry(
                vm_start=0x400000,
                vm_end=0x500000,
                vm_pgoff=0x1000,
                dso_inode=99,
                path=b"/this/path/does/not/exist/myapp",
            )]
        }
        with symbolizer.Symbolizer(maps) as sym:
            result = sym.resolve(7, 0x400100)
        # offset = (0x400100 - 0x400000) + 0x1000 = 0x1100
        self.assertEqual(result, "myapp+0x1100")


if __name__ == "__main__":
    unittest.main(verbosity=2)
