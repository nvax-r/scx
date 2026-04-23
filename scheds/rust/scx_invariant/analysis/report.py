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
/* Timeline (§3) — color legend rendered above the inlined SVG. */
.timeline-legend {
  font-size: 0.85rem;
  color: #555;
  margin: 0 0 0.5rem;
  display: flex;
  gap: 1rem;
  align-items: center;
  flex-wrap: wrap;
}
.timeline-legend .swatch {
  display: inline-block;
  width: 0.75rem;
  height: 0.75rem;
  border-radius: 2px;
  margin-right: 0.3rem;
  vertical-align: middle;
}
.timeline-banner {
  font-size: 0.85rem;
  color: #555;
  margin: 0 0 0.5rem;
  font-style: italic;
}
.timeline-empty {
  color: #888;
  font-style: italic;
}
.timeline-fallback {
  color: #b45309;
  background: #fffbeb;
  border: 1px solid #fcd34d;
  padding: 0.5rem 0.75rem;
  border-radius: 4px;
}
.timeline-fallback code {
  background: #fef3c7;
  padding: 0.05rem 0.3rem;
  border-radius: 2px;
}
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


# --- §3 Thread timeline -----------------------------------------------------
#
# Per-PID swim lanes (running / runnable / sleeping bands over time), sorted
# by total on-CPU time descending. Three thread-count tiers govern detail:
# ≤500 render all, 500..2000 render all + dense-banner, >2000 top-500 + one
# aggregate row. State derivation walks each PID's events in timestamp order
# and emits one band per state transition.

# State labels (also keys into _TIMELINE_COLORS).
_STATE_RUNNING  = "running"
_STATE_RUNNABLE = "runnable"
_STATE_SLEEPING = "sleeping"

_TIMELINE_COLORS = {
    _STATE_RUNNING:  "#60a5fa",  # blue
    _STATE_RUNNABLE: "#fbbf24",  # amber
    _STATE_SLEEPING: "#334155",  # slate, de-emphasized
}

_TIER1_LIMIT = 500    # render all, no banner
_TIER2_LIMIT = 2000   # render all, dense-banner
# n > _TIER2_LIMIT  → render top _TIER1_LIMIT + 1 aggregate row


def _per_pid_events(events: list) -> dict:
    """Group raw events by PID and sort each list by timestamp.

    Returns {pid: [(ts, evt_type, payload), ...]} with each list sorted
    ascending by ts. Events whose payload fails to parse are dropped — the
    parser is the gatekeeper for "is this a valid event with a usable PID".
    """
    by_pid: dict = {}
    for evt_type, payload in events:
        parsed = trace.parse_event(evt_type, payload)
        if not parsed:
            continue
        pid = parsed["pid"]
        ts = parsed["timestamp_ns"]
        by_pid.setdefault(pid, []).append((ts, evt_type, payload, parsed))
    # Stable timestamp sort. Cross-ringbuf delivery is not time-ordered;
    # this is the canonical place to fix that for downstream walking.
    for pid in by_pid:
        by_pid[pid].sort(key=lambda r: r[0])
    return by_pid


def _intervals_for_pid(sorted_events: list, trace_end_ns: int) -> list:
    """Walk a single PID's timestamp-sorted event list and emit bands.

    Returns a list of (t0_ns, t1_ns, state) tuples in execution order.
    Rules from work/task.md:
      - RUNNING  → opens running
      - RUNNABLE → opens runnable
      - QUIESCENT→ opens sleeping
      - STOPPING → opens sleeping if voluntary, else runnable
    First event opens at its own ts (no backward extrapolation). Final
    band closes at trace_end_ns. Same-state-to-same-state transitions
    coalesce into one band.
    """
    intervals = []
    state = None
    t_open = None

    for (ts, evt_type, _payload, parsed) in sorted_events:
        if evt_type == trace.EVT_RUNNING:
            new_state = _STATE_RUNNING
        elif evt_type == trace.EVT_RUNNABLE:
            new_state = _STATE_RUNNABLE
        elif evt_type == trace.EVT_QUIESCENT:
            new_state = _STATE_SLEEPING
        elif evt_type == trace.EVT_STOPPING:
            # Either evt_stopping.voluntary (u8) or hdr.flags &
            # FLAG_VOLUNTARY carries the same info per main.bpf.c —
            # use the explicit per-event field.
            new_state = (_STATE_SLEEPING if parsed.get("voluntary", 0)
                         else _STATE_RUNNABLE)
        else:
            continue  # unknown type — leave state unchanged

        if state is None:
            state = new_state
            t_open = ts
            continue

        if new_state != state:
            intervals.append((t_open, ts, state))
            state = new_state
            t_open = ts
        # else: coalesce same-state event (e.g. duplicate RUNNING) by
        # leaving t_open untouched. Real producers shouldn't emit those
        # but the model is robust either way.

    if state is not None and t_open is not None and t_open < trace_end_ns:
        intervals.append((t_open, trace_end_ns, state))

    return intervals


def _running_duration(intervals: list) -> int:
    """Sum of all running-state interval lengths. Used as the primary sort key."""
    return sum(t1 - t0 for (t0, t1, st) in intervals if st == _STATE_RUNNING)


def _merge_intervals(spans: list) -> list:
    """Sweep-line merge of (t0, t1) into non-overlapping intervals.

    Used for the tier-3 aggregate row: union of running intervals across
    all tail PIDs. Concurrent-on-different-CPUs producers create
    overlapping bands that would visually double-count.
    """
    if not spans:
        return []
    spans = sorted(spans)
    merged = [list(spans[0])]
    for t0, t1 in spans[1:]:
        if t0 <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], t1)
        else:
            merged.append([t0, t1])
    return [tuple(s) for s in merged]


def _build_swimlane_svg(rows: list, trace_duration_ns: int) -> str:
    """Render rows into an inlined <svg> via matplotlib broken_barh.

    rows: list of dicts {"label": str, "intervals": [(t0,t1,state),...]}
    in render order (top row first). Caller has already applied tiering
    and aggregate-row construction.

    Returns the <svg>...</svg> fragment with the XML/DOCTYPE prolog
    stripped, ready to inline inside <section id="timeline">.

    Lazy-imports matplotlib so module top-level stays cheap and the
    fail-soft path can short-circuit. Raises ImportError if matplotlib
    is unavailable (caller catches and renders fallback).
    """
    import io
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    n = len(rows)
    # Per spec: row_h scales with n so the figure stays under ~40" tall
    # even at the upper end of tier 2.
    row_h = max(0.08, min(0.25, 40.0 / max(n, 1)))
    fig_h = max(4.0, n * row_h + 1.0)
    fig_w = 16.0

    # Anchor each row at y = (n - 1 - i) * row_h so row index 0 (busiest)
    # appears at the TOP of the chart.
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")

    yticks = []
    yticklabels = []
    duration_s = trace_duration_ns / 1e9 if trace_duration_ns > 0 else 1.0

    for i, row in enumerate(rows):
        y_bottom = (n - 1 - i) * row_h
        # Group spans by state so each color is one broken_barh call.
        by_state: dict = {
            _STATE_RUNNING:  [],
            _STATE_RUNNABLE: [],
            _STATE_SLEEPING: [],
        }
        for (t0, t1, st) in row["intervals"]:
            if st in by_state and t1 > t0:
                by_state[st].append((t0 / 1e9, (t1 - t0) / 1e9))
        for st, spans in by_state.items():
            if spans:
                ax.broken_barh(spans, (y_bottom, row_h),
                               facecolors=_TIMELINE_COLORS[st],
                               linewidth=0)
        yticks.append(y_bottom + row_h / 2)
        yticklabels.append(row["label"])

    ax.set_xlim(0, duration_s)
    ax.set_ylim(0, n * row_h)
    ax.set_yticks(yticks)
    # Font size scales with row_h so labels stay legible at any tier.
    label_fontsize = max(5.0, min(9.0, row_h * 40))
    ax.set_yticklabels(yticklabels, fontsize=label_fontsize)
    ax.set_xlabel("Time since trace start (s)")
    ax.tick_params(axis="x", labelsize=8)
    ax.grid(axis="x", color="#e5e5e5", linewidth=0.5)
    ax.set_axisbelow(True)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)

    buf = io.BytesIO()
    fig.savefig(buf, format="svg", bbox_inches="tight")
    plt.close(fig)
    raw = buf.getvalue().decode("utf-8")

    # Strip XML prolog and DOCTYPE — neither belongs inside an HTML5
    # body. Find the first '<svg' and return from there.
    svg_start = raw.find("<svg")
    if svg_start == -1:
        # matplotlib gave us something we don't recognise; surface it
        # rather than silently empty-render.
        raise RuntimeError("matplotlib SVG output missing <svg> root")
    return raw[svg_start:]


def _timeline_legend_html() -> str:
    swatches = []
    for state in (_STATE_RUNNING, _STATE_RUNNABLE, _STATE_SLEEPING):
        swatches.append(
            f'<span><span class="swatch" '
            f'style="background:{_TIMELINE_COLORS[state]}"></span>'
            f'{html.escape(state)}</span>'
        )
    return f'<p class="timeline-legend">{" ".join(swatches)}</p>'


def _section_timeline(hdr: dict, events: list, procs: dict) -> str:
    """§3 — per-PID swim-lane timeline. Replaces the Task-2 stub."""
    by_pid = _per_pid_events(events)

    if not by_pid:
        return (
            '<section id="timeline">\n'
            '  <h2>Thread timeline</h2>\n'
            '  <p class="timeline-empty">no per-thread events recorded</p>\n'
            '</section>'
        )

    # Defensive trace_end: spec says ts_end - ts_start, or max event ts
    # if ts_end is zero. Widen to also handle traces where events go
    # past ts_end (clock skew / finalize race) so bands never have
    # negative length.
    max_ev_ts = max(rec[0] for recs in by_pid.values() for rec in recs)
    ts_start = hdr.get("ts_start", 0) or 0
    if hdr.get("ts_end", 0):
        nominal = hdr["ts_end"] - ts_start
    else:
        nominal = 0
    trace_end_abs = max(ts_start + nominal, max_ev_ts)
    trace_duration_ns = max(trace_end_abs - ts_start, 0)
    if trace_duration_ns == 0:
        return (
            '<section id="timeline">\n'
            '  <h2>Thread timeline</h2>\n'
            '  <p class="timeline-empty">trace has zero duration</p>\n'
            '</section>'
        )

    # Build per-PID intervals in absolute ns, then relativize to ts_start
    # so X axis starts at 0.
    pid_intervals = {}
    for pid, recs in by_pid.items():
        abs_iv = _intervals_for_pid(recs, trace_end_abs)
        rel_iv = [(t0 - ts_start, t1 - ts_start, st) for (t0, t1, st) in abs_iv]
        pid_intervals[pid] = rel_iv

    # Sort: primary by sum of running intervals desc, secondary by pid asc.
    sorted_pids = sorted(
        pid_intervals.keys(),
        key=lambda p: (-_running_duration(pid_intervals[p]), p),
    )
    n = len(sorted_pids)

    banner_html = ""
    if n <= _TIER1_LIMIT:
        head_pids = sorted_pids
        tail_pids: list = []
    elif n <= _TIER2_LIMIT:
        head_pids = sorted_pids
        tail_pids = []
        banner_html = (
            f'<p class="timeline-banner">{n} threads — chart may be dense '
            f'(sort: total on-CPU time)</p>'
        )
    else:
        head_pids = sorted_pids[:_TIER1_LIMIT]
        tail_pids = sorted_pids[_TIER1_LIMIT:]

    rows = []
    for pid in head_pids:
        comm = procs.get(pid)
        label = f"{pid} ({comm})" if comm else str(pid)
        rows.append({"label": label, "intervals": pid_intervals[pid]})

    if tail_pids:
        # Aggregate row: union of running intervals only. Skip
        # runnable/sleeping per spec — they would blur into solid fill
        # once unioned across hundreds of PIDs.
        tail_running = []
        for pid in tail_pids:
            for (t0, t1, st) in pid_intervals[pid]:
                if st == _STATE_RUNNING:
                    tail_running.append((t0, t1))
        merged = _merge_intervals(tail_running)
        rows.append({
            "label": f"other ({len(tail_pids)} threads)",
            "intervals": [(t0, t1, _STATE_RUNNING) for (t0, t1) in merged],
        })

    try:
        svg = _build_swimlane_svg(rows, trace_duration_ns)
    except ImportError:
        # matplotlib not installed — fail soft. Report still builds.
        return (
            '<section id="timeline">\n'
            '  <h2>Thread timeline</h2>\n'
            '  <p class="timeline-fallback">matplotlib not installed — '
            '<code>pip install -r analysis/requirements.txt</code></p>\n'
            '</section>'
        )

    parts = ['<section id="timeline">\n', '  <h2>Thread timeline</h2>\n']
    if banner_html:
        parts.append(f'  {banner_html}\n')
    parts.append(f'  {_timeline_legend_html()}\n')
    parts.append(f'  {svg}\n')
    parts.append('</section>')
    return "".join(parts)


def _render(trace_path: str, hdr: dict, topology: list,
            events: list, procs: dict) -> str:
    sections = [_section_overview(trace_path, hdr, events, procs)]
    for sid, title in _TOC_ENTRIES[1:]:
        if sid == "timeline":
            sections.append(_section_timeline(hdr, events, procs))
        else:
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
