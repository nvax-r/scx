#!/usr/bin/env python3
"""
symbolizer.py — Resolve (pid, ip) → 'function_name' using the ProcMaps
section + persistent addr2line subprocesses.

Standalone module; consumed by `analysis/report.py` to label the
wakeup-graph nodes and the new "Thread stack profile" section.

Design notes (matching docs/superpowers/specs/2026-05-12-stack-sample-thread-annotation-design.md §6):

* **Persistent addr2line per DSO.** Spawning a fresh `addr2line` per
  query is the canonical slow-Python footgun; `perf script` solves it
  the same way we do here. The subprocess is created on first hit for
  that DSO path, kept open, and fed file-offset queries on stdin.

* **Per-(pid, ip) cache.** Two PIDs can have the same IP land in
  different DSOs (different ASLR layouts, different libraries loaded
  at different addresses), so we key on (pid, ip), not ip alone.

* **Mapping lookup is binary search** over the per-PID maps sorted by
  vm_start. Each MapEntry covers a [vm_start, vm_end) half-open
  range — IPs at the upper boundary belong to the next mapping (or
  fall into the unmapped fallback if there is no next one).

* **Fallbacks** (per design §7):
  - addr2line returns "??" → render as `dso_name+0x<offset>`
  - DSO path missing on the analyzer's filesystem → same fallback
  - IP not covered by any mapping → render as `0x<ip> [unmapped]`

This is purely user-stack symbolization. Kernel stacks are out of
scope per design §10.
"""

import bisect
import os
import subprocess
import sys
from pathlib import Path

# Sibling import — same idiom report.py / reader.py use.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import trace  # noqa: E402


__all__ = ["Symbolizer"]


# Cap on the number of persistent addr2line processes a Symbolizer
# will spawn. Each one is roughly 5-15 MB resident (address-space
# mapped binary + symbol tables); 64 covers the typical workload's
# DSO set with margin (libc, libpthread, libstdc++, dozens of plugin
# .so's). Past the cap we still resolve via fallback paths.
_MAX_ADDR2LINE_PROCS = 64

# addr2line is normally instant; a stuck process would block the
# report indefinitely. We accept that as a v1 limitation rather than
# building a per-stream residual-buffer + select-based reader (the
# straightforward `readline()` is sufficient for healthy binaries,
# and the report is single-shot — Ctrl-C is the recovery path).


class Symbolizer:
    """Resolve (pid, ip) → human-readable function name.

    Construction is cheap — no addr2line processes are spawned until
    `resolve()` is first called for an IP that maps into a real DSO.

    Thread-safety: not thread-safe. The current report.py is
    single-threaded; if a future caller needs concurrent resolves,
    add a lock around the cache + subprocess dict.
    """

    def __init__(self, proc_maps):
        # proc_maps: {pid: [MapEntry, ...]} as produced by trace.read_sections.
        self._maps = proc_maps
        # Per-PID sorted (vm_start, idx) for binary search. Built lazily.
        self._sorted_starts: dict = {}
        # (pid, ip) -> function name string.
        self._addr_cache: dict = {}
        # DSO path -> Popen handle (or None if spawn failed for this path).
        self._addr2line: dict = {}

    def resolve(self, pid, ip):
        """Return a printable symbol string for (pid, ip).

        Never raises — falls back to a synthetic name on every error
        path so the report can always render.
        """
        key = (pid, ip)
        cached = self._addr_cache.get(key)
        if cached is not None:
            return cached

        result = self._resolve_uncached(pid, ip)
        self._addr_cache[key] = result
        return result

    def _resolve_uncached(self, pid, ip):
        entry = self._lookup_mapping(pid, ip)
        if entry is None:
            return f"0x{ip:x} [unmapped]"

        # File offset = (ip - vm_start) + vm_pgoff.
        # vm_pgoff for executable mappings is the byte offset into
        # the file at which the mapping starts (kernel reports it in
        # bytes for /proc/<pid>/maps).
        file_offset = (ip - entry.vm_start) + entry.vm_pgoff

        path_str = entry.path.decode("utf-8", errors="replace") if entry.path else ""
        if not path_str:
            # Anonymous mapping (heap, stack, anonymous mmap, JIT).
            return f"[anon]+0x{file_offset:x}"

        # Bracketed pseudo-DSOs ([vdso], [vsyscall]) are not files
        # addr2line can read. Fall through to the dso+offset
        # fallback so the user at least sees what mapping the IP
        # landed in.
        if path_str.startswith("["):
            return f"{path_str}+0x{file_offset:x}"

        proc = self._get_addr2line(path_str)
        if proc is None:
            return f"{_basename(path_str)}+0x{file_offset:x}"

        symbol = self._query_addr2line(proc, path_str, file_offset)
        if symbol is None or symbol in ("??", ""):
            return f"{_basename(path_str)}+0x{file_offset:x}"
        return symbol

    def _lookup_mapping(self, pid, ip):
        entries = self._maps.get(pid)
        if not entries:
            return None
        sorted_starts = self._sorted_starts.get(pid)
        if sorted_starts is None:
            # One-shot sort and keep parallel arrays of (vm_start, idx).
            indexed = sorted(range(len(entries)),
                             key=lambda i: entries[i].vm_start)
            sorted_starts = ([entries[i].vm_start for i in indexed], indexed)
            self._sorted_starts[pid] = sorted_starts

        starts, order = sorted_starts
        i = bisect.bisect_right(starts, ip) - 1
        if i < 0:
            return None
        entry = entries[order[i]]
        if entry.vm_start <= ip < entry.vm_end:
            return entry
        return None

    def _get_addr2line(self, dso_path):
        """Return a persistent addr2line process for `dso_path`, or None."""
        if dso_path in self._addr2line:
            return self._addr2line[dso_path]

        if len(self._addr2line) >= _MAX_ADDR2LINE_PROCS:
            # Cap reached — record None so we don't spawn-attempt repeatedly.
            self._addr2line[dso_path] = None
            return None

        if not os.path.isfile(dso_path):
            self._addr2line[dso_path] = None
            return None

        try:
            proc = subprocess.Popen(
                ["addr2line", "-C", "-f", "-e", dso_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,  # line-buffered
            )
        except (FileNotFoundError, OSError):
            # `addr2line` itself missing, or permission denied on the
            # binary. Cache the failure.
            self._addr2line[dso_path] = None
            return None

        self._addr2line[dso_path] = proc
        return proc

    def _query_addr2line(self, proc, dso_path, file_offset):
        """Send one offset to addr2line; return the function name."""
        try:
            proc.stdin.write(f"0x{file_offset:x}\n")
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            self._kill_addr2line(dso_path)
            return None

        # addr2line -f emits two lines per query:
        #   <function name>
        #   <source:line>
        # We only need the first line; drain the second so the next
        # query reads from a clean position.
        try:
            func_line = proc.stdout.readline()
            proc.stdout.readline()
        except (OSError, ValueError):
            self._kill_addr2line(dso_path)
            return None

        if not func_line:
            self._kill_addr2line(dso_path)
            return None

        return func_line.strip()

    def _kill_addr2line(self, dso_path):
        proc = self._addr2line.get(dso_path)
        if proc is not None:
            try:
                proc.kill()
            except OSError:
                pass
        self._addr2line[dso_path] = None

    def close(self):
        """Reap every persistent addr2line subprocess."""
        for path, proc in list(self._addr2line.items()):
            if proc is None:
                continue
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is None:
                    continue
                try:
                    stream.close()
                except (OSError, AttributeError):
                    pass
            try:
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except OSError:
                    pass
                try:
                    proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass
            self._addr2line[path] = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _basename(path):
    return os.path.basename(path) or path
