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
/* Heatmap (§2) — same fallback / empty-state idiom as the timeline. */
.heatmap-note {
  font-size: 0.85rem;
  color: #555;
  margin: 0 0 0.5rem;
  font-style: italic;
}
.heatmap-empty { color: #888; font-style: italic; }
.heatmap-fallback {
  color: #b45309;
  background: #fffbeb;
  border: 1px solid #fcd34d;
  padding: 0.5rem 0.75rem;
  border-radius: 4px;
}
.heatmap-fallback code {
  background: #fef3c7;
  padding: 0.05rem 0.3rem;
  border-radius: 2px;
}
/* Wakeup graph (§4) — graphviz-rendered, three failure modes, all
   degrade to a sidecar .dot file + clear message. */
.wakeups-banner {
  font-size: 0.85rem;
  color: #555;
  margin: 0 0 0.5rem;
  font-style: italic;
}
.wakeups-empty { color: #888; font-style: italic; }
.wakeups-fallback {
  color: #b45309;
  background: #fffbeb;
  border: 1px solid #fcd34d;
  padding: 0.5rem 0.75rem;
  border-radius: 4px;
}
.wakeups-fallback code {
  background: #fef3c7;
  padding: 0.05rem 0.3rem;
  border-radius: 2px;
}
.wakeups-fallback pre {
  background: #fef3c7;
  padding: 0.5rem;
  border-radius: 2px;
  overflow-x: auto;
  font-size: 0.8rem;
  margin: 0.5rem 0 0;
}
.wakeups-svg-wrapper {
  overflow-x: auto;
  max-width: 100%;
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


# --- §2 CPU heatmap --------------------------------------------------------
#
# Per-CPU busy fraction over time. Driven exclusively by EVT_STOPPING events
# (their runtime_ns is the truth source). Rows are NUMA/LLC/cpu_id-sorted so
# imbalance reads at a glance, with thin separator lines between NUMA blocks.

# n_buckets is min(500, max(1, duration_ns // 1ms)). At 5s → 500 buckets
# (~10ms each); at 100ms → 100 buckets (~1ms each).
_HEATMAP_MAX_BUCKETS = 500


def _cpu_render_order(topology: list, nr_cpus: int) -> tuple:
    """Return (cpu_order, numa_breaks) for the heatmap's row layout.

    cpu_order: list of cpu_ids in render order (top → bottom).
    numa_breaks: list of row indices where a NUMA block transition starts;
                 the renderer draws a thin separator above each.

    Defensive fallbacks:
      - empty topology  → natural [0, nr_cpus) order, no separators.
      - cpu_ids in [0, nr_cpus) missing from topology → appended at end
        (synthetic numa/llc = -1) so the heatmap row count always matches
        nr_cpus.
    """
    if not topology:
        return list(range(nr_cpus)), []

    by_cpu = {t["cpu_id"]: t for t in topology}
    seen = set(by_cpu.keys())
    sorted_known = sorted(
        topology, key=lambda t: (t["numa_id"], t["llc_id"], t["cpu_id"])
    )
    cpu_order = [t["cpu_id"] for t in sorted_known]
    # Append any CPU id in [0, nr_cpus) that the topology section omitted.
    for c in range(nr_cpus):
        if c not in seen:
            cpu_order.append(c)

    numa_breaks: list = []
    prev_numa = None
    for i, c in enumerate(cpu_order):
        cur_numa = by_cpu.get(c, {}).get("numa_id")
        if i > 0 and cur_numa != prev_numa:
            numa_breaks.append(i)
        prev_numa = cur_numa
    return cpu_order, numa_breaks


def _add_to_buckets(matrix_row: list, t_start: float, t_stop: float,
                    bucket_width: float, n_buckets: int) -> None:
    """Distribute one running interval into bucket fractions (in place).

    Both timestamps are trace-relative ns. `t_start` and `t_stop` are
    clipped to [0, n_buckets * bucket_width] so events past the trace
    window can't index OOB. Half-open right edge — an interval ending
    exactly on a bucket boundary belongs to the previous bucket.
    """
    span_end_ns = n_buckets * bucket_width
    if t_start < 0:
        t_start = 0
    if t_stop > span_end_ns:
        t_stop = span_end_ns
    if t_stop <= t_start:
        return

    first_b = int(t_start // bucket_width)
    # Half-open: subtract a tiny epsilon so a stop on the boundary lands
    # in the previous bucket. Bounded by n_buckets - 1 in case of float
    # rounding pushing us past the last index.
    last_b = min(n_buckets - 1, int((t_stop - 1e-9) // bucket_width))

    if first_b == last_b:
        matrix_row[first_b] += (t_stop - t_start) / bucket_width
        return

    matrix_row[first_b] += ((first_b + 1) * bucket_width - t_start) / bucket_width
    for b in range(first_b + 1, last_b):
        matrix_row[b] += 1.0
    matrix_row[last_b] += (t_stop - last_b * bucket_width) / bucket_width


def _build_busy_matrix(nr_cpus: int, events: list, ts_start: int,
                       duration_ns: int, n_buckets: int,
                       cpu_to_row: dict) -> tuple:
    """Build the (nr_cpus × n_buckets) busy-fraction matrix.

    cpu_to_row maps a raw cpu_id (from the event's `cpu` field) to the
    matrix row index, so callers can keep the matrix laid out in
    NUMA/LLC/cpu_id render order without a second permutation pass.

    Returns (matrix, max_pre_clamp_value) so the caller can decide whether
    to emit the "overlapping quanta" stderr warning.
    """
    bucket_width = duration_ns / n_buckets if n_buckets else 1.0
    matrix = [[0.0] * n_buckets for _ in range(nr_cpus)]

    n_stopping = 0
    for evt_type, payload in events:
        if evt_type != trace.EVT_STOPPING:
            continue
        parsed = trace.parse_event(evt_type, payload)
        if not parsed:
            continue
        n_stopping += 1
        cpu_id = parsed["cpu"]
        row = cpu_to_row.get(cpu_id)
        if row is None or row >= nr_cpus:
            continue  # event references a cpu not in our render set
        runtime_ns = parsed.get("runtime_ns", 0)
        if runtime_ns <= 0:
            continue
        t_stop = parsed["timestamp_ns"] - ts_start
        t_start = t_stop - runtime_ns
        _add_to_buckets(matrix[row], t_start, t_stop, bucket_width, n_buckets)

    # Clamp; capture the worst overshoot for the stderr warning.
    max_seen = 0.0
    for row in matrix:
        for b in range(n_buckets):
            if row[b] > max_seen:
                max_seen = row[b]
            if row[b] > 1.0:
                row[b] = 1.0
    return matrix, max_seen, n_stopping


def _build_heatmap_svg(matrix: list, cpu_order: list, numa_breaks: list,
                       duration_ns: int) -> str:
    """Render the busy-fraction matrix into an inlined <svg>.

    Lazy-imports matplotlib (raises ImportError if unavailable so the
    caller's fail-soft path can short-circuit). Strips the XML/DOCTYPE
    prolog for inlining inside HTML5 <body>.
    """
    import io
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    nr_cpus = len(cpu_order)
    fig_h = min(20.0, max(4.0, nr_cpus * 0.1))
    fig_w = 16.0
    duration_s = duration_ns / 1e9 if duration_ns > 0 else 1.0

    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")

    # extent puts seconds on X for free (no tick remapping).
    im = ax.imshow(
        matrix,
        aspect="auto",
        interpolation="nearest",
        cmap="viridis",
        vmin=0.0,
        vmax=1.0,
        extent=(0.0, duration_s, nr_cpus, 0.0),
    )

    # Y labels: every 16 rows for nr_cpus ≥ 32, every 8 below; always
    # include first and last. Label values are the actual cpu_id at that
    # row (cpu_order may be NUMA-shuffled, so row index ≠ cpu_id).
    step = 16 if nr_cpus >= 32 else 8
    rows_to_label = list(range(0, nr_cpus, step))
    if (nr_cpus - 1) not in rows_to_label:
        rows_to_label.append(nr_cpus - 1)
    ax.set_yticks([r + 0.5 for r in rows_to_label])
    ax.set_yticklabels([str(cpu_order[r]) for r in rows_to_label],
                       fontsize=7)
    ax.set_ylabel("CPU id")
    ax.set_xlabel("Time since trace start (s)")
    ax.tick_params(axis="x", labelsize=8)

    # NUMA separators: thin semi-transparent lines between blocks.
    for row in numa_breaks:
        ax.axhline(y=row, color="white", linewidth=0.6, alpha=0.55)

    # Narrow colorbar on the right.
    cbar = fig.colorbar(im, ax=ax, fraction=0.012, pad=0.01)
    cbar.set_label("fraction busy", fontsize=8)
    cbar.ax.tick_params(labelsize=7)

    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)

    buf = io.BytesIO()
    fig.savefig(buf, format="svg", bbox_inches="tight")
    plt.close(fig)
    raw = buf.getvalue().decode("utf-8")
    svg_start = raw.find("<svg")
    if svg_start == -1:
        raise RuntimeError("matplotlib SVG output missing <svg> root")
    return raw[svg_start:]


def _section_heatmap(hdr: dict, topology: list, events: list) -> str:
    """§2 — per-CPU busy-fraction heatmap. Replaces the Task-2 stub."""
    nr_cpus = hdr.get("nr_cpus", 0) or 0
    if nr_cpus <= 0:
        return (
            '<section id="heatmap">\n'
            '  <h2>CPU heatmap</h2>\n'
            '  <p class="heatmap-empty">no CPU topology recorded</p>\n'
            '</section>'
        )

    # Defensive trace_end widening, same shape as Task 3.
    ts_start = hdr.get("ts_start", 0) or 0
    nominal = (hdr["ts_end"] - ts_start) if hdr.get("ts_end", 0) else 0
    max_ev_ts = 0
    for evt_type, payload in events:
        parsed = trace.parse_event(evt_type, payload)
        if parsed and parsed["timestamp_ns"] > max_ev_ts:
            max_ev_ts = parsed["timestamp_ns"]
    duration_ns = max(nominal, max_ev_ts - ts_start, 0)
    if duration_ns <= 0:
        return (
            '<section id="heatmap">\n'
            '  <h2>CPU heatmap</h2>\n'
            '  <p class="heatmap-empty">trace has zero duration</p>\n'
            '</section>'
        )

    n_buckets = min(_HEATMAP_MAX_BUCKETS,
                    max(1, duration_ns // 1_000_000))

    cpu_order, numa_breaks = _cpu_render_order(topology, nr_cpus)
    cpu_to_row = {cpu: i for i, cpu in enumerate(cpu_order)}

    matrix, max_seen, n_stopping = _build_busy_matrix(
        nr_cpus, events, ts_start, duration_ns, n_buckets, cpu_to_row,
    )

    # Spec: ε-overshoot is silent; anything farther means physically
    # overlapping quanta on one CPU (shouldn't happen). One-line stderr
    # warning, no spam.
    if max_seen > 1.0 + 1e-6:
        print(
            f"report.py: heatmap cell sum exceeded 1.0 (max={max_seen:.4f}); "
            f"clamped — possible overlapping quanta on one CPU",
            file=sys.stderr,
        )

    note_html = ""
    if n_stopping == 0:
        note_html = ('<p class="heatmap-note">'
                     'no stopping events — all CPUs idle for the recorded window'
                     '</p>')

    try:
        svg = _build_heatmap_svg(matrix, cpu_order, numa_breaks, duration_ns)
    except ImportError:
        return (
            '<section id="heatmap">\n'
            '  <h2>CPU heatmap</h2>\n'
            '  <p class="heatmap-fallback">matplotlib not installed — '
            '<code>pip install -r analysis/requirements.txt</code></p>\n'
            '</section>'
        )

    parts = ['<section id="heatmap">\n', '  <h2>CPU heatmap</h2>\n']
    if note_html:
        parts.append(f'  {note_html}\n')
    parts.append(f'  {svg}\n')
    parts.append('</section>')
    return "".join(parts)


# --- §4 Wakeup graph -------------------------------------------------------
#
# Directed graph of "thread A woke thread B" edges, weighted by count.
# Rendered by shelling out to graphviz `dot`. Optional system dep — three
# failure modes (missing / timeout / dot-error) each degrade to a .dot
# sidecar file + a clear HTML message; the overall report still exits 0.

# Color hash for nodes — fixed per-PID so the same PID gets the same color
# across re-renders. Local to report.py for now; if a v2 timeline wants
# cross-chart consistency it can lift this out.
_PALETTE = ["#60a5fa", "#fbbf24", "#34d399", "#f472b6",
            "#a78bfa", "#fb7185", "#facc15", "#22d3ee"]

def _color_for_pid(pid: int) -> str:
    return _PALETTE[pid % len(_PALETTE)]


_WAKEUPS_TOP_N = 100
_WAKEUPS_DOT_TIMEOUT_S = 30


def _collect_wakeup_edges(events: list) -> dict:
    """Walk events once. Return {(waker_pid, wakee_pid): count}.

    Source: EVT_RUNNING events whose parsed waker_pid is non-zero. The
    wakee is the event's own pid (the kernel's select_cpu attributed
    that wakeup). Other event types are ignored.
    """
    edges: dict = {}
    for evt_type, payload in events:
        if evt_type != trace.EVT_RUNNING:
            continue
        parsed = trace.parse_event(evt_type, payload)
        if not parsed:
            continue
        waker = parsed.get("waker_pid", 0)
        if not waker:
            continue
        wakee = parsed["pid"]
        key = (waker, wakee)
        edges[key] = edges.get(key, 0) + 1
    return edges


def _dot_escape(s: str) -> str:
    """Escape a string for inclusion inside a dot quoted-label.

    Defensive against `\\`, `"` and embedded newlines / control chars
    that the kernel's comm field could in principle carry. Note: callers
    that want a literal newline in the rendered label use `\\n`
    (two chars in the source string) which dot interprets — that is
    NOT escaped here.
    """
    return (s.replace("\\", "\\\\")
             .replace('"', '\\"')
             .replace("\n", " ")
             .replace("\r", " ")
             .replace("\t", " "))


def _render_dot_source(edges: dict, procs: dict) -> str:
    """Build the dot source string for a (capped) edge dict.

    Node and edge styling:
      - rankdir=LR — waker→wakee reads left-to-right.
      - bgcolor=transparent — blends with the HTML section background.
      - per-node color: hash-of-pid via _color_for_pid.
      - node label: "<pid>\\n<comm>" or just "<pid>" when comm is
        unknown.
      - node width: 0.4 + 0.15 * log(total + 1), height auto so the
        label always fits.
      - edge label: integer count.
      - edge penwidth: max(1.0, log(count + 1)).
      - edge color: single neutral slate (#94a3b8).

    `total` per PID is summed over the edges that survived the top-N
    cap, so node size matches what the graph actually shows.
    """
    import math

    # Aggregate over surviving edges only — keeps node sizes coherent
    # with the displayed edge set.
    totals: dict = {}
    pids: set = set()
    for (waker, wakee), count in edges.items():
        pids.add(waker)
        pids.add(wakee)
        totals[waker] = totals.get(waker, 0) + count
        totals[wakee] = totals.get(wakee, 0) + count

    lines = ["digraph wakeups {",
             "  rankdir=LR;",
             "  bgcolor=transparent;",
             '  node [shape=box, style=filled, fontname="monospace", fontsize=11];',
             '  edge [color="#94a3b8"];']

    # Sorted iteration so the output is deterministic — easier to diff
    # across runs and easier to test.
    for pid in sorted(pids):
        comm = procs.get(pid)
        if comm:
            label = f'{pid}\\n{_dot_escape(comm)}'
        else:
            label = str(pid)
        width = 0.4 + 0.15 * math.log(totals.get(pid, 0) + 1)
        lines.append(
            f'  n{pid} [label="{label}", '
            f'fillcolor="{_color_for_pid(pid)}", '
            f'width={width:.3f}];'
        )

    for (waker, wakee), count in sorted(edges.items(),
                                        key=lambda kv: (-kv[1], kv[0])):
        penwidth = max(1.0, math.log(count + 1))
        lines.append(
            f'  n{waker} -> n{wakee} [label="{count}", '
            f'penwidth={penwidth:.2f}];'
        )

    lines.append("}")
    return "\n".join(lines) + "\n"


def _render_via_dot(dot_source: str) -> tuple:
    """Shell out to `dot -Tsvg`. Returns a tagged-union (status, payload).

    status ∈ {"ok", "err_missing", "err_timeout", "err_dot"}.
    payload is the SVG string for "ok", an error-detail string (possibly
    empty) for the err_* variants. Caller composes the HTML message and
    decides whether to write the .dot sidecar.
    """
    import subprocess
    try:
        result = subprocess.run(
            ["dot", "-Tsvg"],
            input=dot_source.encode("utf-8"),
            capture_output=True,
            timeout=_WAKEUPS_DOT_TIMEOUT_S,
            check=True,
        )
    except FileNotFoundError:
        return ("err_missing", "")
    except subprocess.TimeoutExpired:
        return ("err_timeout", "")
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or b"").decode("utf-8", errors="replace")[:500]
        return ("err_dot", stderr)

    raw = result.stdout.decode("utf-8", errors="replace")
    svg_start = raw.find("<svg")
    if svg_start == -1:
        return ("err_dot", "dot output missing <svg> root")
    return ("ok", raw[svg_start:])


def _write_dot_sidecar(out_path: str, dot_source: str) -> str:
    """Write the dot source to <out_path>.wakeups.dot. Returns the path
    (or an empty string if the write failed, which is logged to stderr
    but doesn't abort the report)."""
    sidecar = out_path + ".wakeups.dot"
    try:
        Path(sidecar).write_text(dot_source, encoding="utf-8")
        return sidecar
    except OSError as e:
        print(f"report.py: could not write dot sidecar {sidecar}: {e}",
              file=sys.stderr)
        return ""


def _section_wakeups(hdr: dict, events: list, procs: dict,
                     out_path: str) -> str:
    """§4 — wakeup graph rendered via graphviz `dot`. Replaces the stub."""
    edges = _collect_wakeup_edges(events)

    if not edges:
        return (
            '<section id="wakeups">\n'
            '  <h2>Wakeup graph</h2>\n'
            '  <p class="wakeups-empty">no waker data recorded — either the '
            'workload did no wakeups, or select_cpu was not observed for any '
            'running transition</p>\n'
            '</section>'
        )

    total_edges = len(edges)
    banner_html = ""
    if total_edges > _WAKEUPS_TOP_N:
        # Keep the top-N by count, ties broken by lexicographic edge.
        kept = dict(sorted(edges.items(),
                           key=lambda kv: (-kv[1], kv[0]))[:_WAKEUPS_TOP_N])
        banner_html = (
            f'<p class="wakeups-banner">showing top {_WAKEUPS_TOP_N} of '
            f'{total_edges} wakeup edges</p>'
        )
    else:
        kept = edges

    dot_source = _render_dot_source(kept, procs)
    status, payload = _render_via_dot(dot_source)

    if status == "ok":
        parts = ['<section id="wakeups">\n', '  <h2>Wakeup graph</h2>\n']
        if banner_html:
            parts.append(f'  {banner_html}\n')
        parts.append('  <div class="wakeups-svg-wrapper">\n')
        parts.append(f'    {payload}\n')
        parts.append('  </div>\n')
        parts.append('</section>')
        return "".join(parts)

    # All err_* paths: write the .dot sidecar, render fallback message.
    sidecar = _write_dot_sidecar(out_path, dot_source)
    sidecar_note = ""
    if sidecar:
        sidecar_rel = os.path.basename(sidecar)
        sidecar_note = (f' Source written to <code>{html.escape(sidecar_rel)}'
                        f'</code>.')

    if status == "err_missing":
        body = (
            'graphviz <code>dot</code> not found on PATH — install it '
            '(e.g. <code>apt install graphviz</code>) to get the '
            f'rendered graph.{sidecar_note}'
        )
    elif status == "err_timeout":
        body = (
            f'graphviz <code>dot</code> timed out '
            f'(&gt;{_WAKEUPS_DOT_TIMEOUT_S}s) — graph probably too large to '
            f'render.{sidecar_note} Try <code>sfdp -Tsvg</code> or reduce '
            f'the top-edges cap.'
        )
    else:  # err_dot
        body = (
            f'graphviz <code>dot</code> failed.{sidecar_note}'
            f'<pre>{html.escape(payload)}</pre>'
        )

    parts = ['<section id="wakeups">\n', '  <h2>Wakeup graph</h2>\n']
    if banner_html:
        parts.append(f'  {banner_html}\n')
    parts.append(f'  <p class="wakeups-fallback">{body}</p>\n')
    parts.append('</section>')
    return "".join(parts)


def _render(trace_path: str, hdr: dict, topology: list,
            events: list, procs: dict, out_path: str) -> str:
    sections = [_section_overview(trace_path, hdr, events, procs)]
    for sid, title in _TOC_ENTRIES[1:]:
        if sid == "timeline":
            sections.append(_section_timeline(hdr, events, procs))
        elif sid == "heatmap":
            sections.append(_section_heatmap(hdr, topology, events))
        elif sid == "wakeups":
            sections.append(_section_wakeups(hdr, events, procs, out_path))
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
        rendered = _render(args.trace, hdr, topology, events, procs, out)
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
