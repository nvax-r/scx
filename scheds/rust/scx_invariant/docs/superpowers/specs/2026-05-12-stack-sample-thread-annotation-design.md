# scx_invariant — Stack-sample thread annotation (design)

Date: 2026-05-12 (re-baselined the same day after code review)
Status: spec — implementation in flight
Author: Richard Cheng

## §1 — Goal

Every thread that appears in a `.scxi` trace gains a **hot user-stack annotation**, computed offline from per-quantum stack samples. The first consumer is the wakeup-graph node label, which grows from `{pid, comm}` to `{pid, comm, top_fn, ↳ caller, ↳ grand_caller}` (truncated to 2-3 frames). The same data powers a new "Thread stack profile" section of the HTML report.

This addresses the operator complaint: today the wakeup graph shows `pid + comm` and nothing else, so a reader cannot tell what each thread *does* in the workload. The new annotation answers "what function does this thread run" without leaving the existing report flow.

The mechanism keeps scx_invariant's scheduler-invariant principle intact — captured signals are properties of the workload, not artifacts of the running scheduler.

## §2 — Architecture

```
BPF (src/bpf/main.bpf.c)
  ops.stopping            → existing EVT_STOPPING (unchanged)
                          → bpf_get_task_stack(p, &ip[16], 128, BPF_F_USER_STACK)
                          → emit EVT_SAMPLE wire form (160 B: hdr + walk_ret + pad + ip[16])
  ops.init_task           → emit EVT_PROC_NEW (pid, tgid, ppid, in-kernel comm)  [SLEEPABLE]
  tp_btf/sched_process_exec → emit EVT_PROC_EXEC (pid in hdr)
                                |
                                ▼
Rust consumer thread (recorder.rs::handle_event, single-threaded, 1 ms poll)
  - For EVT_PROC_NEW / EVT_PROC_EXEC : enqueue snapshot request → worker thread
  - For EVT_SAMPLE                   : hash IP[] → userspace stack_id, write 32 B disk record
  - For other events                 : if PID unknown, enqueue snapshot request and tag partial-identity
  - All events written to disk in arrival order
                                |
                                ▼
Rust snapshot worker thread (new in this design)
  - Drains a bounded SyncSender<(u32, EventType)> queue
  - Reads /proc/<pid>/{maps, cmdline} and updates procs_seen (Mutex)
  - Decoupled from ringbuf draining, so /proc IO latency doesn't back-pressure events
                                |
                                ▼
Rust cold path (output.rs::finalize)
  - Section 0x0004 ProcMaps    — per-PID executable mappings
  - Section 0x0005 ProcStacks  — userspace stack_id → IP[] dedup table
  - Section 0x0002 (process table) is permanently retired; pid → comm lives in EVT_PROC_NEW
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
  Symbolizer: ProcMaps + addr2line per DSO (persistent process per DSO, in-mem cache)
  Render:
    • Wakeup-graph node label: pid + comm + 2-3 hot-stack frames
    • New "Thread stack profile" section: top-N stacks per thread with counts
```

The 24-byte `scx_invariant_event` header on each new event carries `(timestamp_ns, pid, tgid, cpu, event_type, flags)`. Attribution is stateless — every event identifies its own subject without paired-event lookup.

## §3 — ABI additions

### New event types (occupy 0x0104–0x0106 in the event-ID namespace)

| ID     | Name           | Wire size | Disk size | Trigger                  | Payload                                  |
|--------|----------------|-----------|-----------|--------------------------|------------------------------------------|
| 0x0104 | `EVT_PROC_NEW`  | 56 B      | 56 B      | `ops.init_task` (SLEEPABLE) | hdr(24) + ppid(4) + comm[16] + pad(12) |
| 0x0105 | `EVT_PROC_EXEC` | 24 B      | 24 B      | `tp_btf/sched_process_exec` | hdr(24) only — pid lives in hdr        |
| 0x0106 | `EVT_SAMPLE`    | 160 B     | 32 B      | `ops.stopping`              | wire: hdr + walk_ret + pad + ip[16]; disk: hdr + stack_id + pad |

`EVT_SAMPLE` is the one event whose BPF-to-userspace wire form differs from its on-disk form. The BPF program writes the inline IP[16] array directly into the ringbuf payload because the kernel-side `bpf_get_stackid()` helper is not available to sched_ext struct_ops programs (see §4). The recorder hashes the IP[] in userspace, assigns a per-trace `stack_id`, and writes a compact 32 B disk record. The full IP[] → stack_id dedup table is dumped in the `ProcStacks` section at finalize.

```c
struct evt_proc_new {
    struct scx_invariant_event hdr;   /* event_type = EVT_PROC_NEW */
    u32 ppid;                          /* real_parent->tgid (see "real_parent vs parent" below) */
    u8  comm[16];                      /* in-kernel p->comm via BPF_CORE_READ_INTO */
    u32 pad[3];                        /* total: 56 B */
};

struct evt_proc_exec {
    struct scx_invariant_event hdr;   /* event_type = EVT_PROC_EXEC, total: 24 B */
};

/* BPF→userspace wire form (160 B). */
struct evt_sample {
    struct scx_invariant_event hdr;   /* event_type = EVT_SAMPLE */
    s32 walk_ret;                      /* bpf_get_task_stack() return: ≥ 0 byte count, or -errno */
    u32 pad;
    u64 ip[STACK_DEPTH_MAX];           /* STACK_DEPTH_MAX = 16; zero-padded for shallow walks */
};

/* Disk form (32 B) — produced by the userspace recorder after hashing ip[]:
 *   hdr(24) + stack_id:s32(4) + pad:u32(4)
 *
 * Negative walk_ret (BPF walk failed) is written through as a negative
 * stack_id; the IP[] is not stored on disk for failed walks.
 */
```

#### real_parent vs parent

`evt_proc_new.ppid` is `BPF_CORE_READ(p, real_parent, tgid)` — `real_parent` is the natural forker, while `task_struct::parent` is the `SIGCHLD`-recipient parent, which diverges from `real_parent` only when the task has been ptrace'd. The wakeup-graph mental model is "who forked this thread", not "who is wait4()-ing on it", so `real_parent` is correct. Without this choice spelled out, a future reader of the code might "simplify" to `parent` and silently break the ptrace case.

### New file-format sections (occupy 0x0004, 0x0005)

| ID     | Name         | Written at | Body                                                   |
|--------|--------------|------------|--------------------------------------------------------|
| 0x0004 | `ProcMaps`   | finalize   | per-PID executable mappings (only `x`-perm entries)    |
| 0x0005 | `ProcStacks` | finalize   | userspace stack_id → IP[] dedup table                  |

`ProcMaps` body (per-PID record, sorted by PID for deterministic output):
```
[pid: u32][n_maps: u16][pad: u16]
n_maps × {
    [vm_start: u64][vm_end: u64][vm_pgoff: u64]
    [dso_inode: u64]
    [path_len: u16][path: bytes]   /* path_len = 0 for anon mappings */
}
```

`ProcStacks` body (per-stack record, sorted by `stack_id` for deterministic output):
```
[stack_id: u32][depth: u8][pad: u8 × 3]
depth × [ip: u64]
```

### Section removed

The previous **process table** (section 0x0002) is removed. The same `(pid, comm)` mapping is reconstructed from the `EVT_PROC_NEW` event stream by the analyzer; `EVT_PROC_EXEC` indicates a later identity refresh. The 0x0002 section ID is permanently retired and must not be re-used for any future section.

## §4 — BPF hot path

Three new BPF entry points in `src/bpf/main.bpf.c`.

### Why `bpf_get_task_stack`, not `bpf_get_stackid`

`bpf_get_stackid()` is **not callable** from sched_ext struct_ops programs in this kernel. `kernel/sched/ext.c:7656` sets `.get_func_proto = bpf_base_func_proto`, and `kernel/bpf/helpers.c::bpf_base_func_proto` (lines 2052–2230) does not include `BPF_FUNC_get_stackid` in any switch arm. The four `bpf_get_stackid_proto*` variants are wired only into the kprobe / tracepoint / perf-event / raw_tp paths in `kernel/trace/bpf_trace.c`. Additionally, `bpf_get_stackid_proto` requires `arg1_type = ARG_PTR_TO_CTX` (a `struct pt_regs *`) which sched_ext callbacks never supply.

What is available: `BPF_FUNC_get_task_stack` (in `bpf_base_func_proto` at `kernel/bpf/helpers.c:2217-2221`, sleepable variant selected automatically when `prog->sleepable`). It takes a BTF-verified task pointer and writes the IP[] array directly into a caller-provided buffer. There's no kernel-side stack-id dedup; that moves into userspace.

`BPF_F_FAST_STACK_CMP` is a `bpf_get_stackid` flag (kernel-side hash-compare vs memcmp) and does not apply to `bpf_get_task_stack`. Only `BPF_F_USER_STACK` is meaningful for `bpf_get_task_stack` in this design (kernel stacks are out of scope per §10).

### Per-task identity notification — `invariant_init_task` (SLEEPABLE)

```c
s32 BPF_STRUCT_OPS_SLEEPABLE(invariant_init_task,
                              struct task_struct *p,
                              struct scx_init_task_args *args)
{
    if (!p)
        return 0;

    u32 cpu = bpf_get_smp_processor_id();
    struct evt_proc_new *e = rb_reserve(cpu, sizeof(*e));
    if (!e) {
        rb_drop_inc();
        return 0;                            /* never fail init_task */
    }
    fill_hdr(&e->hdr, p, EVT_PROC_NEW);
    e->ppid = BPF_CORE_READ(p, real_parent, tgid);
    /* BPF_CORE_READ_INTO is cheaper than bpf_probe_read_kernel_str
     * (no CAP_PERFMON gate) and the comm field is fixed-size 16 B. */
    BPF_CORE_READ_INTO(&e->comm, p, comm);
    rb_submit(e);
    return 0;
}
```

`ops.init_task` fires twice in this scheduler's lifecycle:
1. **Synchronous attach pass** — when scx_invariant loads, `kernel/sched/ext.c::scx_init_and_enable_tasks()` walks every eligible task in the system and calls `ops.init_task` for each one *before* any of them runs under our scheduler.
2. **Fork path** — `kernel/fork.c::sched_fork()` → `scx_fork()` → `__scx_init_task()` → `ops.init_task(p, args)`. This fires from within `copy_process()` at `kernel/fork.c:2231`, before `attach_pid()` at line 2504.

So the BPF event is emitted **before `/proc/<pid>` is set up** in the fork path. The userspace polling thread doesn't read `/proc` until at least 1 ms later (poll cadence), by which point `attach_pid()` has long since completed. The fork-vs-attach race is therefore subsumed by the 1 ms userspace poll latency in practice. The race that *does* exist is the smaller window where a process forks, runs, and exits faster than the consumer thread reaches its event — covered by `no_maps` in §8.

### Exec notification — `invariant_proc_exec` (`tp_btf/sched_process_exec`)

```c
SEC("tp_btf/sched_process_exec")
int BPF_PROG(invariant_proc_exec, struct task_struct *p, u32 old_pid,
             struct linux_binprm *bprm)
{
    if (!p)
        return 0;
    u32 cpu = bpf_get_smp_processor_id();
    struct evt_proc_exec *e = rb_reserve(cpu, sizeof(*e));
    if (!e) {
        rb_drop_inc();
        return 0;
    }
    fill_hdr(&e->hdr, p, EVT_PROC_EXEC);
    rb_submit(e);
    return 0;
}
```

Signature lifted from `include/trace/events/sched.h::sched_process_exec`. Body carries no payload beyond the standard 24-byte header — PID lives in `hdr`.

### Per-quantum stack sample — appended to existing `invariant_stopping`

```c
void BPF_STRUCT_OPS(invariant_stopping, struct task_struct *p, bool runnable)
{
    /* ... existing EVT_STOPPING emission unchanged ... */

    struct evt_sample *sevt = rb_reserve(cpu, sizeof(*sevt));
    if (sevt) {
        fill_hdr(&sevt->hdr, p, EVT_SAMPLE);
        sevt->pad = 0;
        __builtin_memset(sevt->ip, 0, sizeof(sevt->ip));
        long ret = bpf_get_task_stack(p, sevt->ip, sizeof(sevt->ip),
                                      BPF_F_USER_STACK);
        sevt->walk_ret = (s32)ret;
        rb_submit(sevt);
    } else {
        rb_drop_inc();
    }
}
```

Two ringbuf submissions per stopping (`EVT_STOPPING` + `EVT_SAMPLE`); both via `BPF_RB_NO_WAKEUP` to keep the per-event IPI cost out of the hot path.

### `fill_hdr` helper and `bpf_get_smp_processor_id`

The header initializer is consolidated into a single inline function:

```c
static __always_inline void fill_hdr(struct scx_invariant_event *hdr,
                                      struct task_struct *p, u16 event_type)
{
    hdr->timestamp_ns = scx_bpf_now();
    hdr->pid = p->pid;
    hdr->tgid = p->tgid;
    hdr->cpu = bpf_get_smp_processor_id();
    hdr->event_type = event_type;
    hdr->flags = 0;
}
```

Choice of `bpf_get_smp_processor_id()` over `scx_bpf_task_cpu(p)`: the two match during the existing struct_ops callbacks (which run on `p`'s CPU). For `init_task` and the `sched_process_exec` tracepoint, `p->cpu` may not yet reflect the running CPU, while `bpf_get_smp_processor_id()` is well-defined in every BPF context.

### Cgroup-gating policy for the three new events

- `EVT_PROC_NEW` and `EVT_PROC_EXEC` are **not** cgroup-gated. The analyzer needs proc-table identity for any task the user might later see scheduling events for via the cgroup gate (and for the scheduler-attach synchronous pass, where we want every task indexed regardless of which cgroup they'll later run in).
- `EVT_SAMPLE` is implicitly cgroup-gated because it lives inside `invariant_stopping`, which already returns early for non-target tasks.

### `SCX_OPS_DEFINE` change

```c
SCX_OPS_DEFINE(invariant_ops,
               ...
               .init_task = (void *)invariant_init_task,
               ...);
```

`sched_process_exec` is a tp_btf attach, not a struct_ops op — it's registered via its `SEC` declaration.

## §5 — Userspace recorder

`output.rs` and `recorder.rs` changes. The consumer thread stays as cheap as today; per-PID `/proc` snapshotting moves to a dedicated worker thread to avoid back-pressuring the ringbuf drain.

### Removed

- The first-sight comm-from-`/proc/<pid>/comm` read in `output.rs::write_event` (in-kernel `p->comm` via `EVT_PROC_NEW` is authoritative now).
- The process-table section emission at finalize.

### Two-thread architecture (new in this revision)

**Consumer thread** (existing, polls 6 ringbufs every 1 ms):
```rust
fn handle_event(data: &[u8]) -> i32 {
    let event_type = u16::from_le_bytes([data[20], data[21]]);
    let pid = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

    match event_type {
        EVT_PROC_NEW | EVT_PROC_EXEC => {
            snapshot_tx.send((pid, SnapKind::Refresh)).ok();
        }
        EVT_SAMPLE => {
            writer.write_sample_event(data, pid)?;
            return 0;                                  /* sample fully handled here */
        }
        _ => {
            if !writer.procs_seen.contains_key(&pid) {
                snapshot_tx.send((pid, SnapKind::FirstSight)).ok();
                writer.mark_partial_identity(pid);
            }
        }
    }
    writer.write_event(data)?;
    0
}
```

**Snapshot worker** (new, dedicated thread, drains a bounded channel):
```rust
fn snapshot_worker(rx: Receiver<(u32, SnapKind)>, procs: Arc<Mutex<HashMap<u32, ProcInfo>>>) {
    for (pid, kind) in rx.iter() {
        let info = snapshot_proc(pid);              /* /proc reads, can be slow */
        let mut procs = procs.lock().unwrap();
        match kind {
            SnapKind::Refresh    => { procs.insert(pid, info); }
            SnapKind::FirstSight => { procs.entry(pid).or_insert(info).partial_identity = true; }
        }
    }
}
```

The channel is bounded (e.g., 1024 entries) so a runaway fork burst that outpaces the worker drops snapshot *requests* (not events) — events still land on disk in order. Dropped snapshots produce empty `ProcInfo` with `no_maps = true`, which the analyzer surfaces honestly.

The cost we pay is one extra atomic per event (channel send is uncontended in the common case). The cost we *don't* pay is `/proc/<pid>/maps` parse time on the consumer thread, which is the existing 1 ms poll's natural budget and the existing scheme's hot-path discipline.

### `snapshot_proc` (worker-thread side)

- Parse `/proc/<pid>/maps`, keep only mappings with `x` perm.
- Read `/proc/<pid>/cmdline` (small, single read).
- On ENOENT / ESRCH (process already gone), return `ProcInfo` with `no_maps = true`. No retry — by the time we reach this path the process is either present or terminated; there's nothing to wait for.

### EVT_SAMPLE wire→disk transformation (consumer thread)

```rust
fn write_sample_event(&mut self, data: &[u8], pid: u32) -> Result<()> {
    let walk_ret = i32::from_le_bytes([data[24], data[25], data[26], data[27]]);

    let stack_id: i32 = if walk_ret < 0 {
        walk_ret                                       /* preserve -errno */
    } else {
        let mut ips = decode_ip_array(&data[32..], walk_ret as usize / 8);
        while ips.last() == Some(&0) { ips.pop(); }     /* strip trailing zero frames */
        let next_id = self.stack_ids.len() as u32;
        *self.stack_ids.entry(ips).or_insert(next_id) as i32
    };

    write_disk_record(EVT_SAMPLE, &data[..24], stack_id)
}
```

The userspace `stack_ids: HashMap<Vec<u64>, u32>` is the dedup table. Insertion order = numeric order of `stack_id`s; finalize sorts by `stack_id` for a stable on-disk record sequence.

### `finalize` (cold path)

```rust
fn finalize(&mut self) -> Result<u64> {
    self.writer.flush()?;
    self.write_proc_maps_section()?;            /* §0x0004 */
    self.write_proc_stacks_section()?;          /* §0x0005 */
    self.patch_header_end_ts()?;
    Ok(self.event_count)
}
```

No `/proc` reads at finalize — short-lived processes are already gone, and re-reading would only refresh data we've already symbolized from.

## §6 — Python analyzer

Three changes, decoupled.

### `analysis/trace.py` — parser additions

```python
SECTION_PROC_MAPS    = 0x0004
SECTION_PROC_STACKS  = 0x0005

EVT_PROC_NEW   = 0x0104
EVT_PROC_EXEC  = 0x0105
EVT_SAMPLE     = 0x0106

# After parse_trace(), the returned trace exposes:
#   trace.proc_maps   : dict[int, list[MapEntry]]
#   trace.proc_stacks : dict[int, list[int]]      # stack_id → [ip, ...]
# Events list includes EVT_PROC_NEW / EVT_PROC_EXEC / EVT_SAMPLE entries.
# The old process-table parser path is removed.
```

`MapEntry` is a namedtuple `(vm_start, vm_end, vm_pgoff, dso_inode, path)`.

### Two-pass analysis

Pass 1 builds the proc table from `EVT_PROC_NEW` / `EVT_PROC_EXEC`. Pass 2 processes scheduling events with the proc table in hand. The events list must be in memory for both passes (~tens of MB for a typical recording — fine), so this is not a streaming parser.

```python
def build_proc_table(events):
    table = {}
    for e in events:
        if e.type == EVT_PROC_NEW:
            table[e.pid] = {"comm": e.comm, "ppid": e.ppid, "execs": 0}
        elif e.type == EVT_PROC_EXEC:
            entry = table.setdefault(e.pid, {"comm": "?", "ppid": 0, "execs": 0})
            entry["execs"] += 1
    return table
```

PIDs missing from the proc table after pass 1 (because `EVT_PROC_NEW` was dropped on a full ring buffer) are tagged `partial-identity` — same tag the recorder uses.

### `analysis/symbolizer.py` — new module

```python
class Symbolizer:
    """Resolve (pid, ip) → 'function_name' using ProcMaps + addr2line."""

    def __init__(self, proc_maps: dict[int, list[MapEntry]]):
        self._maps = proc_maps
        self._cache: dict[tuple[int, int], str] = {}            # (pid, ip) → name
        self._addr2line: dict[str, subprocess.Popen] = {}        # dso path → persistent process

    def resolve(self, pid: int, ip: int) -> str:
        ...                                                       # see hot-stack derivation below
```

- **Persistent `addr2line -C -f` per DSO** — spawning per query is the slow-Python footgun. One subprocess per DSO with stdin/stdout pipes handles thousands of queries per second.
- **Cache by `(pid, ip)`** — different processes can have different libraries at different addresses.
- **DSO path lookup** — paths come from the recording host's filesystem. If the binary isn't on the analyzer's filesystem, fall back to `dso_name+0x<offset>`. No copy-binaries-into-trace story in v1.
- **Demangling** — `addr2line -C -f` covers C++ and Rust.

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

### New "Thread stack profile" section

`<section id="stack-profile">` placed between today's per-thread timeline and the wakeup graph. One sub-table per top-N thread (default N=20 by total sample count). Columns: rank · sample count + % · top frame · caller · grand-caller. Click-through expands each row to the full 16-frame stack.

### PID-state tags (single canonical vocabulary)

The recorder may attach two non-orthogonal tags to a PID, and both are rendered as a yellow row tint in the stack-profile table with a one-line annotation in the per-thread header. Definitions:

- **`partial-identity`** — the PID's identity is incomplete because *some* of its identity-producing event(s) didn't reach us. Concretely set when (a) the recorder saw a scheduling event for a PID before its `EVT_PROC_NEW` arrived (notification dropped on a full ring buffer or out-of-order arrival), or (b) `/proc/<pid>` was already gone when the snapshot worker ran. The analyzer treats these uniformly: do the best we can with what's available, render `[unmapped]` for unresolvable IPs.
- **`stale-maps after exec`** — the PID had an `EVT_PROC_EXEC`, but the post-exec maps re-snapshot failed (process exited before the worker could re-read `/proc/<pid>/maps`). Pre-exec maps are still in the trace; any post-exec stacks may symbolize wrongly.

### Fallback render states

| state                                   | render                                             |
|-----------------------------------------|----------------------------------------------------|
| no samples (process exited before any quantum) | falls back to today's `pid + comm` only  |
| stacks captured, no maps (ephemeral process)  | `0x7f8a... [unmapped]`; tag `partial-identity` |
| maps present, binary stripped                  | `dso_name+0x<file_offset>`                     |
| post-exec maps refresh failed                  | `partial-identity` + `stale-maps after exec` |

### Truncation and demangling rules

- Frame names truncated to **40 chars** in graph nodes, **120 chars** in the stack-profile table (demangled C++/Rust names get long).
- Demangling via `addr2line -C -f`.
- Anonymous mappings render as `[anon]+0x<offset>`.
- Kernel-mode stacks are not captured in v1 (user stacks only via `BPF_F_USER_STACK`).

## §8 — Error handling and edge cases

| Case | Detection | Behavior |
|---|---|---|
| `bpf_get_task_stack` returns negative | `evt_sample.walk_ret < 0` | Wire value flows through as negative `stack_id` on disk. Analyzer counts these per PID and surfaces a "failed walks" counter in the stack-profile header. |
| `EVT_PROC_NEW` ringbuf reserve fails | `bpf_ringbuf_reserve` returns NULL | Notification skipped; `rb_drop_inc()` counter increments. Fallback first-sight in the consumer dispatches a snapshot request; PID tagged `partial-identity`. |
| `/proc/<pid>` gone when worker runs (**dominant case for sub-ms processes**) | `snapshot_proc` returns `no_maps = true` | `procs_seen.insert(pid, ProcInfo { no_maps: true, .. })`. Analyzer renders `[unmapped]` and tags `partial-identity`. Note: this is the *primary* outcome for ephemeral processes (`sh -c 'true'`, single-syscall binaries) — not a rare edge case. |
| `EVT_PROC_EXEC` arrives, maps re-read fails | ESRCH on re-snapshot | Keep pre-exec maps. PID tagged `stale-maps after exec`. Post-exec stacks may symbolize wrongly. |
| Snapshot worker queue full | `SyncSender::send` errors | Drop the snapshot request silently. PID falls through the first-sight fallback path on its next scheduling event (or stays unsymbolized if no further events arrive). |
| Binary missing at report time | `addr2line` exits / no info | Falls back to `dso_name+0x<offset>`. |
| Stripped binary | `addr2line` returns `??` | Same `dso_name+0x<offset>` fallback. `addr2line -C -f --inlines` still tries `.dynsym`. |
| Stack truncated at `STACK_DEPTH_MAX` (16) | walk_ret = 128 (16 × 8) | Render ellipsis marker after the last frame in the stack-profile expansion. |
| Userspace stack_ids HashMap grows unbounded | by design | The map is the dedup table; bounded by the cardinality of distinct stacks in the trace. Memory is a function of stack diversity, not trace duration. Document if it ever bites; tunable cap (e.g. 65 536 entries with stable-set LRU) is a future addition. |
| BPF_F_FAST_STACK_CMP | not used | Documented in §4: the flag is meaningless for `bpf_get_task_stack` — it's a `bpf_get_stackid` flag and userspace owns stack-id collision policy. |

## §9 — Testing

### Unit tests (Rust, `#[cfg(test)]`)

- `output.rs`: round-trip serializer/parser for `EVT_PROC_NEW`, `EVT_PROC_EXEC`, `EVT_SAMPLE` (wire and disk forms) using handwritten byte vectors.
- `output.rs`: `ProcMaps` section encode/decode for representative `/proc/maps` (small, large, anon-only, path truncation).
- `output.rs`: `ProcStacks` section encode/decode against a fake `HashMap<Vec<u64>, u32>`.
- `output.rs`: `write_sample_event` correctness — negative walk_ret pass-through, stack_id dedup across repeated stacks, trailing-zero stripping.

### Unit tests (Python, `analysis/test_reader.py` + new `analysis/test_symbolizer.py`)

- `trace.py`: parse the new sections from a synthetic `.scxi`.
- `symbolizer.py`:
  - mapping lookup correctness (boundary IPs, contiguous mappings, anon mappings, vdso),
  - `addr2line` persistent-process caching (no re-spawn per query),
  - graceful fallback when binary missing,
  - graceful fallback for stripped binaries (`strip` a tiny binary in `tests/data/`).

### Integration / smoke

- `record stress-ng --cpu 4 --timeout 3` → run `report.py` → assert ≥1 `EVT_PROC_NEW`, ≥1 `EVT_SAMPLE` with non-negative `stack_id`, ≥1 symbolized frame in the wakeup graph.
- `record sh -c 'sleep 0.01; true'` → assert the `true` PID gets tagged `partial-identity` and the report doesn't crash.
- `record` on a fork-heavy workload (`make -j` against a small target) → assert the snapshot worker keeps up: count of `no_maps = true` PIDs stays under a sane fraction (≤ 5%) of total PIDs.

### Hot-path cost gate (before merge)

`time` `record stress-ng --cpu 144 --timeout 10` with and without stack sampling (compile-time flag or `--no-stack-sample`). Compare event throughput and stress-ng BogoOps. Target: **< 5% workload perturbation increase** vs no-stack baseline. Also count ringbuf drops (the existing `drop_counter`); the new stack-sample path doubles per-quantum event count and is the most likely source of drop pressure under load.

## §10 — Out of scope (deferred)

| Item | Why deferred |
|---|---|
| Kernel-mode stacks | Different analysis target (sleep-cause attribution). Plumbing is small (drop `BPF_F_USER_STACK`, second walk_ret) but rendering and aggregation deserve their own pass. |
| Per-edge wake-site stacks | Different question (where in the code did the wake fire?). Hot-path lives in `select_cpu`, not `stopping`. Small follow-up once §6 symbolizer is in tree. |
| JIT code (Java, Node, V8) | Consumes `/tmp/perf-<pid>.map` sidecars. Standard perf-tools convention. Add when a JIT workload is on the table. |
| Container / PID namespace awareness | `/proc/<pid>/maps` paths from inside a container differ from host. Adds a path-translation layer to `Symbolizer`. Defer until needed. |
| `dlopen()` mid-trace map snapshots | Maps captured only at `EVT_PROC_NEW` / `EVT_PROC_EXEC`. Later loads → `[unmapped]`. Hook `mmap_region` later if it bites. |
| Frame-pointer-less binaries | Documented limitation. DWARF-CFI unwinding via BPF is a separate large effort. Mitigation: `-fno-omit-frame-pointer` on workloads where it matters. |
| Userspace stack_ids LRU eviction | Long traces with high stack diversity could grow the dedup map unboundedly. Bounded LRU is straightforward to add later if it bites. |
| Cross-CPU event ordering | Scheduler-dependent, not workload-invariant. Analyzer two-pass parse handles arrival order. |

## §11 — Adjacent upstream opportunities (not on this plan's critical path)

Two related upstream items surfaced during this design and were deliberately not attempted:

1. **`BPF_MAP_TYPE_STACK_TRACE` lacks `.map_for_each_callback`.** `kernel/bpf/stackmap.c::stack_trace_map_ops` does not implement `.map_for_each_callback`, so BPF programs cannot use `bpf_for_each_map_elem(&stack_traces, …)`. Independent of scx_invariant — we don't iterate a stack map from inside a BPF program in v1. Adding the op is a small kernel patch; see `work/notes.md` 2026-05-12.

2. **A sched_ext kfunc wrapping `bpf_get_stackid()`.** Would let future sched_ext-based schedulers (this one and others) reuse kernel-side stack-id dedup instead of userspace hashing. Out of scope for this repo — proper home is `linux/kernel/sched/ext.c` upstream.

## §12 — Reference

- Project plan: `scheds/rust/scx_invariant/PLAN.md`
- Glossary: `docs/glossary.md`
- Conventions: `docs/conventions.md`
- Eval: `docs/eval.md`
- Brainstorming session + code review re-baseline: 2026-05-12 (this design doc is the spec output)
