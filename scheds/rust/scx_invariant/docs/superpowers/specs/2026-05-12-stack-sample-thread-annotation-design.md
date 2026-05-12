# scx_invariant — Stack-sample thread annotation (design)

Date: 2026-05-12
Status: spec — pending implementation plan
Author: Richard Cheng

## §1 — Goal

Every thread that appears in a `.scxi` trace gains a **hot user-stack annotation**, computed offline from per-quantum stack samples. The first consumer is the wakeup-graph node label, which grows from `{pid, comm}` to `{pid, comm, top_fn, ↳ caller, ↳ grand_caller}` (truncated to 2-3 frames). The same data powers a new "Thread stack profile" section of the HTML report.

This addresses the operator complaint: today the wakeup graph shows `pid + comm` and nothing else, so a reader cannot tell what each thread *does* in the workload. The new annotation answers "what function does this thread run" without leaving the existing report flow.

The mechanism keeps the scheduler-invariant principle intact: capture the workload's intrinsic code-level identity, not scheduler-policy artifacts.

## §2 — Architecture

```
BPF (src/bpf/main.bpf.c)
  ops.init_task    → emit EVT_PROC_NEW (pid, tgid, ppid, comm)
  ops.stopping     → existing EVT_STOPPING (unchanged)
                   → bpf_get_stackid(BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP)
                   → emit EVT_SAMPLE (pid, stack_id)
  tp_btf/sched_process_exec → emit EVT_PROC_EXEC (pid)
  maps:
    existing 6 events_rb_N         (EVT_PROC_NEW / EVT_PROC_EXEC / EVT_SAMPLE
                                    ride these; routed by cpu_id % 6)
    new BPF_MAP_TYPE_STACK_TRACE   (max_entries tunable; value = 16 × u64)
                                |
                                ▼
Rust hot path (recorder.rs / output.rs)
  - Ring-buffer poll loop dispatches all event types via existing TLV passthrough
  - Pre-write hook for EVT_PROC_NEW / EVT_PROC_EXEC: snapshot
    /proc/<pid>/{maps, cmdline} into procs_seen
                                |
                                ▼
Rust cold path (output.rs::finalize)
  - Section 0x0004 (ProcMaps)   — per-PID executable mappings
  - Section 0x0005 (ProcStacks) — drain BPF stack-trace map
  - Existing process table (section 0x0002) is removed; its contents are
    derivable from the EVT_PROC_NEW stream.
                                |
                                ▼
.scxi file
  Header (unchanged) · Topology (unchanged) · Events (now includes
  EVT_PROC_NEW / EVT_PROC_EXEC / EVT_SAMPLE) · ProcMaps · ProcStacks
                                |
                                ▼
Python analyzer (analysis/trace.py + new symbolizer.py + report.py)
  Pass 1: build pid → {comm, ppid, exec_count} from EVT_PROC_NEW / EVT_PROC_EXEC
  Pass 2: process scheduling events with full proc table in hand
  Symbolizer: ProcMaps + addr2line per DSO (persistent process, cached)
  Render:
    • Wakeup-graph node label: pid + comm + 2-3 hot-stack frames
    • New "Thread stack profile" section: top-N stacks per thread with counts
```

The 24-byte `scx_invariant_event` header on each new event carries `(pid, tgid, cpu, event_type, flags)`, so attribution is stateless — every event identifies its own subject without paired-event lookup.

## §3 — ABI additions

### New event types (occupy 0x0104, 0x0105, 0x0106 in the event-ID namespace)

| ID     | Name           | Total size | Trigger                  | Payload                                       |
|--------|----------------|------------|--------------------------|-----------------------------------------------|
| 0x0104 | `EVT_PROC_NEW`  | 56 B       | `ops.init_task`          | hdr(24) + ppid(4) + comm[16] + pad[12]        |
| 0x0105 | `EVT_PROC_EXEC` | 24 B       | `sched_process_exec` tp  | hdr(24) only — `pid` already in header        |
| 0x0106 | `EVT_SAMPLE`    | 32 B       | `ops.stopping`           | hdr(24) + stack_id (s32) + pad(4)             |

```c
struct evt_proc_new {
    struct scx_invariant_event hdr;   /* event_type = EVT_PROC_NEW */
    u32 ppid;
    u8  comm[16];                     /* in-kernel p->comm */
    u32 pad[3];                       /* pad to 56 B / 8-byte align */
};

struct evt_proc_exec {
    struct scx_invariant_event hdr;   /* event_type = EVT_PROC_EXEC */
};

struct evt_sample {
    struct scx_invariant_event hdr;   /* event_type = EVT_SAMPLE */
    s32 stack_id;                     /* negative = bpf_get_stackid error */
    u32 pad;
};
```

### New file-format sections (occupy 0x0004, 0x0005)

| ID     | Name         | Written at | Body                                                |
|--------|--------------|------------|-----------------------------------------------------|
| 0x0004 | `ProcMaps`   | finalize   | per-PID executable mappings (`x` perm filter)       |
| 0x0005 | `ProcStacks` | finalize   | drained `BPF_MAP_TYPE_STACK_TRACE`                  |

`ProcMaps` body (binary, repeating per-PID record):
```
[pid: u32][n_maps: u16][pad: u16]
n_maps × {
    [vm_start: u64][vm_end: u64][vm_pgoff: u64]
    [dso_inode: u64]
    [path_len: u16][path: bytes]   /* NUL if anon */
}
```

`ProcStacks` body (binary, repeating per-stack record):
```
[stack_id: u32][depth: u8][pad: u8 × 3]
depth × [ip: u64]
```

### Section removed

The current **process table** (section 0x0002) is removed. The same `(pid, comm)` mapping is reconstructed from the `EVT_PROC_NEW` event stream by the analyzer (with `EVT_PROC_EXEC` indicating later identity refresh). One fewer thing to keep synchronized at finalize.

## §4 — BPF hot path

Three new BPF entry points in `src/bpf/main.bpf.c`:

```c
/* (1) Per-task identity notification — fires from copy_process() and from
       the scheduler-attach synchronous pass over existing tasks. */
s32 BPF_STRUCT_OPS_SLEEPABLE(invariant_init_task,
                              struct task_struct *p,
                              struct scx_init_task_args *args)
{
    int rb_idx = bpf_get_smp_processor_id() % NR_RBS;
    struct evt_proc_new *e =
        bpf_ringbuf_reserve(&events_rb[rb_idx], sizeof(*e), 0);
    if (!e)
        return 0;                            /* never fail init_task */
    fill_hdr(&e->hdr, p, EVT_PROC_NEW);
    e->ppid = BPF_CORE_READ(p, real_parent, tgid);
    bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), p->comm);
    bpf_ringbuf_submit(e, BPF_RB_NO_WAKEUP);
    return 0;
}

/* (2) Exec notification — separate hook, not a sched_ext op. */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(invariant_proc_exec, struct task_struct *p, ...)
{
    /* emits EVT_PROC_EXEC; body parallel to (1) modulo no payload */
}

/* (3) Per-quantum stack sample, appended to existing invariant_stopping. */
void BPF_STRUCT_OPS(invariant_stopping, struct task_struct *p, bool runnable)
{
    /* ... existing EVT_STOPPING emission unchanged ... */

    s32 sid = bpf_get_stackid(ctx, &stack_traces,
                              BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);
    int rb_idx = bpf_get_smp_processor_id() % NR_RBS;
    struct evt_sample *e =
        bpf_ringbuf_reserve(&events_rb[rb_idx], sizeof(*e), 0);
    if (!e)
        return;
    fill_hdr(&e->hdr, p, EVT_SAMPLE);
    e->stack_id = sid;
    e->pad = 0;
    bpf_ringbuf_submit(e, BPF_RB_NO_WAKEUP);
}
```

### New BPF map

```c
#define STACK_DEPTH_MAX    16
#define STACK_MAP_ENTRIES  (1 << 14)        /* 16 384 unique stacks; ~2 MiB */

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, STACK_MAP_ENTRIES);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64) * STACK_DEPTH_MAX);
} stack_traces SEC(".maps");
```

### Notes that matter

- `invariant_init_task` is `SLEEPABLE` — needed for `BPF_CORE_READ` / `bpf_probe_read_kernel_str`. sched_ext allows `init_task` to sleep.
- New `fill_hdr()` helper consolidates the existing open-coded header init across `running` / `stopping` / `runnable` / `quiescent` / `sample`. Worth doing as part of this change.
- `BPF_F_FAST_STACK_CMP` uses kernel-side hash compare (vs full-stack `memcmp`). Cheaper hot path; ~0.1% collision risk accepted.
- `EVT_PROC_NEW` / `EVT_SAMPLE` ride the existing 6 ring buffers via `cpu_id % 6`. No new buffers needed.
- **Event ordering within a CPU** is preserved by the kernel's ring buffer. **Cross-CPU ordering is not** and we don't defend it — fork-CPU vs run-CPU placement is scheduler-dependent, not part of workload-invariant identity. Analyzer's two-pass parse handles arrival order (§6).
- `STACK_MAP_ENTRIES` becomes a `--stack-map-entries` CLI knob for long recordings.

## §5 — Userspace recorder

`output.rs` and `recorder.rs` changes. The hot-path writer stays as cheap as today.

### Removed

- The current first-sight comm capture in `write_event` (replaced by `EVT_PROC_NEW`).
- The process-table section emission at finalize (replaced by the event stream).

### Added

```rust
struct ProcInfo {
    maps:    Vec<MapEntry>,         /* captured at EVT_PROC_NEW; refreshed at EVT_PROC_EXEC */
    cmdline: Vec<u8>,               /* /proc/<pid>/cmdline, NUL-separated argv */
    no_maps: bool,                  /* process gone before snapshot succeeded */
}

/* In recorder.rs::handle_event — pre-write hook: */
match event_type {
    EVT_PROC_NEW  => self.snapshot_proc(pid),
    EVT_PROC_EXEC => self.snapshot_proc(pid),   /* re-read after exec */
    _ => {}
}
self.writer.write_event(event_type, payload)?;
```

`snapshot_proc(pid)`:
- parse `/proc/<pid>/maps`, keep only mappings with `x` perm,
- read `/proc/<pid>/cmdline` (small, single read),
- on ESRCH (process already gone), mark `no_maps = true`. No retry.

A small fallback hash check stays in `write_event`: if an event references a PID not in `procs_seen` (dropped `EVT_PROC_NEW` because ring was full), userspace falls back to the old first-sight `/proc` read and tags the PID `partial-identity`.

### finalize (cold path)

```rust
fn finalize(&mut self) -> Result<u64> {
    self.writer.flush()?;
    self.write_proc_maps_section(&self.procs_seen)?;       /* §0x0004 */
    self.write_proc_stacks_section(&self.skel.maps.stack_traces)?;  /* §0x0005 */
    self.patch_header_end_ts()?;
    Ok(self.event_count)
}
```

The stack-map dump iterates via `libbpf-rs::Map::keys()` + `lookup()` per `stack_id`. Each value is 16 × u64; strip trailing zeros and write `[stack_id, depth, ip[]]` records. Iteration cost is proportional to unique stacks, not total samples — the whole point of stack-by-id.

## §6 — Python analyzer

Three changes, decoupled.

### `analysis/trace.py` — parser additions

```python
SECTION_PROC_MAPS    = 0x0004
SECTION_PROC_STACKS  = 0x0005

EVT_PROC_NEW   = 0x0104
EVT_PROC_EXEC  = 0x0105
EVT_SAMPLE     = 0x0106

# After parse_trace(), the returned trace now exposes:
#   trace.proc_maps   : dict[int, list[MapEntry]]
#   trace.proc_stacks : dict[int, list[int]]      # stack_id → [ip, ...]
# Events list includes EVT_PROC_NEW / EVT_PROC_EXEC / EVT_SAMPLE entries.
```

`MapEntry` is a small namedtuple: `(vm_start, vm_end, vm_pgoff, dso_inode, path)`.

### Two-pass analysis

```python
def build_proc_table(events):
    """Pass 1 — pid → {comm, ppid, exec_count}."""
    table = {}
    for e in events:
        if e.type == EVT_PROC_NEW:
            table[e.pid] = {"comm": e.comm, "ppid": e.ppid, "execs": 0}
        elif e.type == EVT_PROC_EXEC:
            entry = table.setdefault(e.pid, {"comm": "?", "ppid": 0, "execs": 0})
            entry["execs"] += 1
    return table
```

Pass 2 processes scheduling events with the full proc-table in hand. Any PID missing from pass 1 → tagged `partial-identity` (covered the EVT_PROC_NEW-was-dropped path).

### `analysis/symbolizer.py` — new module

```python
class Symbolizer:
    """Resolve (pid, ip) → 'function_name' using ProcMaps + addr2line."""

    def __init__(self, proc_maps: dict[int, list[MapEntry]]):
        self._maps = proc_maps
        self._addr_cache: dict[tuple[int, int], str] = {}
        self._addr2line: dict[str, subprocess.Popen] = {}   # DSO → process

    def resolve(self, pid: int, ip: int) -> str:
        ...                                                  # see §5 prose
```

Notes worth nailing down:

- **Persistent `addr2line` per DSO**, not per query. Same trick `perf script` uses. Spawning per IP is the slow-Python footgun.
- **Cache is per `(pid, ip)`** because PID determines which mapping the IP falls in (different processes can have different libraries loaded at different addresses).
- **DSO path lookup**: paths come from the *recording host's* filesystem. If the binary isn't on the analyzer's filesystem, fall back to `dso_name+0x<offset>`. No copy-binaries-into-trace story in v1.
- **Demangling**: `addr2line -C -f` handles C++ and Rust. Good enough.

### Hot-stack derivation

```python
def hot_stacks_per_pid(events, proc_stacks):
    """Return {pid: [(stack_id, count), ...] sorted desc}."""
    counts = defaultdict(Counter)
    for e in events:
        if e.type != EVT_SAMPLE or e.stack_id < 0:
            continue
        counts[e.pid][e.stack_id] += 1
    return {pid: c.most_common() for pid, c in counts.items()}
```

Hot stack = most-common `stack_id` per PID. Top 3 frames of that stack become the wakeup-graph node annotation.

## §7 — HTML report rendering

Two consumers of the symbolized data.

### Wakeup-graph node label (existing graph, extended)

```python
def _node_label(pid, comm, hot_stack):
    lines = [str(pid), _dot_escape(comm)]
    if hot_stack:
        for i, frame in enumerate(hot_stack[:3]):
            prefix = "" if i == 0 else "↳ "
            lines.append(prefix + _dot_escape(_truncate(frame, 40)))
    return "\\n".join(lines)
```

`hot_stack` is `[top_frame, caller, grand_caller]` derived per-PID by the histogram above.

### New "Thread stack profile" section

`<section id="stack-profile">` placed between today's per-thread timeline and the wakeup graph. One sub-table per top-N thread (default N=20 by total sample count):

| #  | samples           | top frame         | caller                | grand-caller     |
|----|-------------------|-------------------|-----------------------|------------------|
| 1  | 2,184 (69.8%)     | `PostgresMain`    | `exec_simple_query`   | `LWLockAcquire`  |
| 2  | 412 (13.2%)       | `WaitLatchOrSocket` | `epoll_wait`        | `__libc_epoll_wait` |
| 3  | 298 (9.5%)        | `smgrread`        | `mdread`              | `FileRead`       |

Click-through expands each row to the full 16-frame stack. Partial-identity rows (frame unresolvable to function name) get a yellow tint.

### Fallback states

| state | render |
|---|---|
| no samples (process exited before any quantum) | falls back to today's `pid + comm` |
| stacks captured, maps gone (sub-ms ephemeral) | `0x7f8a... [unmapped]`; PID tagged `partial-identity` |
| maps present, binary stripped | `dso_name+0x<file_offset>` |

PID-tag definitions (used in the table and in §8):

- `partial-identity` — either (a) PID is missing from the pass-1 proc table because its `EVT_PROC_NEW` was dropped on a full ring buffer, or (b) `procs_seen.no_maps == true` because `/proc/<pid>` was gone by the time userspace tried to snapshot it.
- `stale-maps after exec` — the post-`EVT_PROC_EXEC` maps re-snapshot failed (ESRCH); pre-exec maps remain in the trace and any post-exec stacks may symbolize incorrectly.

### Truncation / demangling rules

- Frame names truncated to **40 chars** in graph nodes, **120 chars** in the Thread stack profile table (demangled C++/Rust names get long).
- Demangling: `addr2line -C -f`. Default for C++/Rust.
- Anonymous mappings: `[anon]+0x<offset>`.
- Kernel stacks not captured in this iteration (user-stack only via `BPF_F_USER_STACK`).

## §8 — Error handling & edge cases

| Case | Detection | Behavior |
|---|---|---|
| `bpf_get_stackid` returns negative | `EVT_SAMPLE.stack_id < 0` | Recorded as-is. Analyzer surfaces per-PID "failed walks" counter. |
| Stack-trace map full | `stack_id == -E2BIG` | Per-CPU counter incremented in BPF; dumped at finalize. Map size is the `--stack-map-entries` knob. |
| `EVT_PROC_NEW` reserve fails (ring full) | `bpf_ringbuf_reserve` returns NULL | Notification skipped. First-sight fallback at next event for that PID. PID tagged `partial-identity`. |
| `EVT_PROC_NEW` arrives, `/proc/<pid>` already gone | snapshot reads return ESRCH | `procs_seen.insert(pid, ProcInfo { no_maps: true, … })`. Analyzer renders `[unmapped]`. |
| `EVT_PROC_EXEC` arrives, maps re-read fails | ESRCH on re-snapshot | Keep pre-exec maps. PID tagged `stale-maps after exec`. |
| Binary missing at report time | `addr2line` returns no info | Falls back to `dso_name+0x<offset>`. |
| Stripped binary | `addr2line` returns `??` | Same DSO+offset fallback. |
| Stack truncated at `STACK_DEPTH_MAX` (16) | kernel returns 16 frames | Ellipsis marker after last frame in stack-profile expansion. |
| Two stacks hash-collide (`BPF_F_FAST_STACK_CMP`) | indistinguishable | Accepted; < 0.1% probability; documented limitation. |

## §9 — Testing

### Unit tests (Rust, `#[cfg(test)]`)

- `output.rs`: round-trip serializer/parser for `EVT_PROC_NEW`, `EVT_PROC_EXEC`, `EVT_SAMPLE` using handwritten byte vectors.
- `output.rs`: `ProcMaps` section encode/decode for representative `/proc/maps` (small, large, anon-only).
- `output.rs`: `ProcStacks` section drain — fake `Vec<(stack_id, Vec<u64>)>` → bytes → re-parse.

### Unit tests (Python, `analysis/test_reader.py` + new `analysis/test_symbolizer.py`)

- `trace.py`: parse the new sections from a synthetic `.scxi`.
- `symbolizer.py`:
  - mapping lookup correctness (boundary IPs, contiguous mappings, anon mappings),
  - `addr2line` caching (no re-spawn per query),
  - graceful fallback when binary missing,
  - graceful fallback for stripped binaries (`strip` a tiny binary in `tests/data/`).

### Integration / smoke

- `record stress-ng --cpu 4 --timeout 3` → run `report.py` → assert ≥1 `EVT_PROC_NEW`, ≥1 `EVT_SAMPLE` with non-negative `stack_id`, ≥1 symbolized frame in the wakeup graph.
- `record sh -c 'sleep 0.01; true'` → assert `true` PID gets `partial-identity` tag; report doesn't crash.
- Determinism: same workload twice → `procs_seen` count stable up to ring-buffer drop noise.

### Hot-path cost (gating before merge)

`time` `record stress-ng --cpu 144 --timeout 10` with vs without stack sampling. Compare event throughput and stress-ng BogoOps. Target: **< 5% workload perturbation increase** vs no-stack baseline.

## §10 — Out of scope (deferred)

| Item | Why deferred |
|---|---|
| Kernel-mode stacks | Different analysis target (sleep-cause attribution). Plumbing trivial (`BPF_F_USER_STACK` → 0, second `stack_id`) but rendering/aggregation deserves its own pass. |
| Per-edge wake-site stacks | Different question (where in the code did the wake fire?). Hot-path lives in `select_cpu`, not `stopping`. Small follow-up once the §6 symbolizer is in tree. |
| JIT code (Java, Node, V8) | Consumes `/tmp/perf-<pid>.map` sidecars. Standard perf-tools convention. Add when a JIT workload is on the table. |
| Container / PID namespace awareness | `/proc/<pid>/maps` paths from inside a container differ from host. Adds a path-translation layer to `Symbolizer`. Defer until needed. |
| `dlopen()` mid-trace map snapshots | Maps captured only at `EVT_PROC_NEW` / `EVT_PROC_EXEC`. Later loads → `[unmapped]`. Hook `mmap_region` later if it bites. |
| Frame-pointer-less binaries | Documented limitation. DWARF-CFI unwinding via BPF is a separate large effort. Mitigation: `-fno-omit-frame-pointer` on workloads where it matters. |
| Stack-map LRU eviction | Kernel `BPF_MAP_TYPE_STACK_TRACE` has no LRU; size budget is the only knob for v1. |
| Cross-CPU event ordering | Scheduler-dependent, hence not workload-invariant. Analyzer two-pass parse handles arrival order. |

## §11 — Adjacent upstream opportunity (not on this plan's critical path)

`BPF_MAP_TYPE_STACK_TRACE` in `kernel/bpf/stackmap.c` does not implement `.map_for_each_callback`, so BPF programs cannot use `bpf_for_each_map_elem(&stack_traces, ...)`. Userspace iteration via `bpf_map_get_next_key()` works fine — only the BPF-side helper is missing. Adding the op is small and self-contained, but not needed for this feature (we dump stacks from userspace at finalize). Parked as an independent upstream contribution.

## §12 — Reference

- Project plan: `scheds/rust/scx_invariant/PLAN.md`
- Glossary: `docs/glossary.md`
- Conventions: `docs/conventions.md`
- Eval: `docs/eval.md`
- Brainstorming session: 2026-05-12 (this design doc is the spec output)
