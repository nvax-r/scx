#!/usr/bin/env python3
"""
report.py — Render an HTML report from an scx_invariant `.scxi` trace.

Section 1 (Overview) is populated from the file header and parsed event
counts. Sections 2–7 are titled stubs that later tasks fill in:

  §2 CPU heatmap          — Task 3
  §3 Thread timeline      — Task 4
  §4 Wakeup graph         — Task 5
  §5 Latency histograms   — Task 3 (alongside heatmap chart work)
  §6 Migration breakdown  — Task 6
  §7 Per-thread table     — Task 6

Stdlib only at this stage; no matplotlib, no graphviz, no external
assets in the rendered HTML (CSS is inlined; favicon is an empty data
URI to suppress the 404 in browser DevTools).

Usage:
    python3 analysis/report.py <trace.scxi> [-o <report.html>]

Default `-o` is `<trace>.report.html` in the trace's directory.
"""

import argparse
import datetime
import html
import os
import sys
from pathlib import Path

# Sibling import; same idiom reader.py / test_reader.py use to keep
# the resolution stable when this script is loaded outside of
# script-execution context (e.g. from a notebook in the repo root).
sys.path.insert(0, str(Path(__file__).resolve().parent))
import trace  # noqa: E402


# Local copy of reader.py's helper. trace.py and reader.py are
# off-limits for this task per work/task.md "MUST NOT touch", and
# duplicating a 7-line function is cheaper than reaching across to a
# CLI script. If a third caller appears, promote this to trace.py in a
# follow-up.
def _format_ns(ns: int) -> str:
    if ns < 1000:
        return f"{ns}ns"
    if ns < 1_000_000:
        return f"{ns / 1000:.1f}us"
    if ns < 1_000_000_000:
        return f"{ns / 1_000_000:.2f}ms"
    return f"{ns / 1_000_000_000:.3f}s"


def _human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KiB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.2f} MiB"
    return f"{n / (1024 * 1024 * 1024):.2f} GiB"


# Inline stylesheet. Two-column grid (sticky 180px TOC + content),
# system font stack, neutral light theme. No JS, no CSS framework, no
# external resources — the rendered HTML opens cleanly from file://
# with zero network requests.
CSS = """\
:root { color-scheme: light; }
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
               Roboto, Helvetica, Arial, sans-serif;
  color: #1a1a1a;
  background: #fafafa;
  line-height: 1.5;
  display: grid;
  grid-template-columns: 180px 1fr;
  min-height: 100vh;
}
nav.toc {
  position: sticky;
  top: 1rem;
  align-self: start;
  padding: 1rem 0.75rem;
  border-right: 1px solid #e5e5e5;
}
nav.toc h2 {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: #666;
  margin: 0 0 0.5rem;
}
nav.toc ol { list-style: none; padding: 0; margin: 0; }
nav.toc li { margin: 0.25rem 0; }
nav.toc a {
  color: #1a1a1a;
  text-decoration: none;
  font-size: 0.9rem;
}
nav.toc a:hover { color: #0066cc; }
main { padding: 1.5rem 2rem; max-width: 1100px; }
h1 { margin: 0 0 1.5rem; font-size: 1.5rem; }
section {
  margin-bottom: 2.5rem;
  scroll-margin-top: 1rem;
}
section h2 {
  font-size: 1.15rem;
  border-bottom: 1px solid #e5e5e5;
  padding-bottom: 0.25rem;
  margin: 0 0 0.75rem;
}
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 0.75rem;
  margin-bottom: 0.5rem;
}
.card {
  background: #fff;
  border: 1px solid #e5e5e5;
  border-radius: 6px;
  padding: 0.6rem 0.8rem;
}
.card .label {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: #777;
}
.card .value {
  font-size: 1rem;
  font-weight: 500;
  margin-top: 0.15rem;
  word-break: break-all;
}
.evt-breakdown {
  font-size: 0.85rem;
  color: #555;
  margin-top: 0.5rem;
}
.stub-note { color: #888; font-style: italic; }
footer {
  grid-column: 2;
  padding: 0 2rem 1.5rem;
  color: #888;
  font-size: 0.8rem;
}
"""


# (anchor_id, display_label) — order is the rendered TOC and section
# order. Anchor IDs are part of the report's external contract: they
# must match the IDs the spec lists so future tasks can link into
# specific sections.
_TOC_ENTRIES = [
    ("overview",   "Overview"),
    ("heatmap",    "CPU heatmap"),
    ("timeline",   "Thread timeline"),
    ("wakeups",    "Wakeup graph"),
    ("histograms", "Latency histograms"),
    ("migrations", "Migration breakdown"),
    ("threads",    "Per-thread table"),
]


def _toc() -> str:
    items = "\n".join(
        f'      <li><a href="#{html.escape(sid)}">{html.escape(title)}</a></li>'
        for sid, title in _TOC_ENTRIES
    )
    return (
        '<nav class="toc" aria-label="Section navigation">\n'
        '  <h2>Sections</h2>\n'
        f'  <ol>\n{items}\n  </ol>\n'
        '</nav>'
    )


def _card(label: str, value: str) -> str:
    return (
        '<div class="card">'
        f'<div class="label">{html.escape(label)}</div>'
        f'<div class="value">{html.escape(value)}</div>'
        '</div>'
    )


def _section_overview(trace_path: str, hdr: dict, events: list, procs: dict) -> str:
    basename = os.path.basename(trace_path)
    try:
        size_bytes = os.stat(trace_path).st_size
    except OSError:
        size_bytes = 0

    if hdr["ts_start"] and hdr["ts_end"] and hdr["ts_end"] > hdr["ts_start"]:
        duration = _format_ns(hdr["ts_end"] - hdr["ts_start"])
    else:
        duration = "—"

    # Distinct-thread count: prefer the procs section (authoritative,
    # written at finalize). Fall back to the set of pids actually seen
    # in events for traces that finalized before procs was populated.
    if procs:
        nthreads = len(procs)
    else:
        pids = set()
        for evt_type, payload in events:
            parsed = trace.parse_event(evt_type, payload)
            if parsed:
                pids.add(parsed["pid"])
        nthreads = len(pids)

    cards = [
        _card("Source",            f"{basename} ({_human_size(size_bytes)})"),
        _card("Host / kernel",     f"{hdr['hostname']} / {hdr['kernel_version']}"),
        _card("Arch / CPUs",       f"{hdr['arch']} / {hdr['nr_cpus']}"),
        _card("Duration",          duration),
        _card("Threads / events",  f"{nthreads} threads · {len(events):,} events"),
    ]

    # Per-type breakdown, suppressing zero-count types. Iterate in
    # lifecycle order (RUNNING → STOPPING → RUNNABLE → QUIESCENT)
    # rather than ID order so the line reads naturally.
    counts: dict = {}
    for evt_type, _ in events:
        counts[evt_type] = counts.get(evt_type, 0) + 1
    parts = []
    for evt_id in (trace.EVT_RUNNING, trace.EVT_STOPPING,
                   trace.EVT_RUNNABLE, trace.EVT_QUIESCENT):
        n = counts.get(evt_id, 0)
        if n:
            parts.append(f"{trace.EVT_NAMES[evt_id]} {n:,}")
    breakdown = " · ".join(parts) if parts else "(no events)"

    return (
        '<section id="overview">\n'
        '  <h2>Overview</h2>\n'
        '  <div class="cards">\n    '
        + "\n    ".join(cards) + "\n"
        '  </div>\n'
        f'  <div class="evt-breakdown">{html.escape(breakdown)}</div>\n'
        '</section>'
    )


def _section_stub(sid: str, title: str,
                  note: str = "rendered by a later task") -> str:
    return (
        f'<section id="{html.escape(sid)}">\n'
        f'  <h2>{html.escape(title)}</h2>\n'
        f'  <p class="stub-note">{html.escape(note)}</p>\n'
        f'</section>'
    )


def _render(trace_path: str, hdr: dict, topology: list,
            events: list, procs: dict) -> str:
    sections = [_section_overview(trace_path, hdr, events, procs)]
    # All non-overview entries become stubs at this stage.
    for sid, title in _TOC_ENTRIES[1:]:
        sections.append(_section_stub(sid, title))

    title = f"scx_invariant report — {html.escape(os.path.basename(trace_path))}"
    generated = datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat(timespec="seconds")

    return (
        '<!DOCTYPE html>\n'
        '<html lang="en">\n'
        '<head>\n'
        '  <meta charset="utf-8">\n'
        '  <meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f'  <title>{title}</title>\n'
        # Empty-data favicon: silences the favicon 404 some browsers
        # log when opening file:// URLs, keeping the report's
        # DevTools console clean.
        '  <link rel="icon" href="data:,">\n'
        f'  <style>\n{CSS}  </style>\n'
        '</head>\n'
        '<body>\n'
        f'{_toc()}\n'
        '<main>\n'
        f'  <h1>{title}</h1>\n'
        + "\n".join(sections) + "\n"
        '</main>\n'
        f'<footer>generated by report.py at {html.escape(generated)}</footer>\n'
        '</body>\n'
        '</html>\n'
    )


def _default_output_path(trace_path: str) -> str:
    p = Path(trace_path)
    if p.suffix == ".scxi":
        return str(p.with_suffix(".report.html"))
    return str(p.with_name(p.name + ".report.html"))


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="report.py",
        description="Render an HTML report from an scx_invariant .scxi trace.",
    )
    parser.add_argument("trace", help="Path to the .scxi trace file.")
    parser.add_argument(
        "-o", "--output",
        help=("Output HTML path. Defaults to <trace>.report.html "
              "in the trace's directory."),
    )
    args = parser.parse_args()

    out = args.output or _default_output_path(args.trace)

    # Parse and render fully in memory before opening the output file.
    # If anything fails we exit non-zero with no partial output left
    # behind — gate 4 in work/task.md.
    try:
        data = Path(args.trace).read_bytes()
        hdr = trace.read_header(data)
        topology, events, procs = trace.read_sections(data, hdr["header_size"])
        rendered = _render(args.trace, hdr, topology, events, procs)
    except trace.UnsupportedVersionError as e:
        print(f"report.py: {e}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as e:
        print(f"report.py: {e}", file=sys.stderr)
        return 1

    Path(out).write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
