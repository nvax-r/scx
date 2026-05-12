#ifndef __INTF_H
#define __INTF_H

#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;
#endif /* __VMLINUX_H__ */

/*
 * Event IDs live at 0x0100+ to stay structurally disjoint from
 * section IDs (SECTION_* in src/output.rs, occupying 0x0001..0x0005).
 * This is the v2 .scxi format invariant — see PLAN.md §5/§6/§11.
 * Do not assign event IDs in the 0x0001..0x00FF range.
 *
 * 0x0104..0x0106 added by the 2026-05-12 stack-sample task:
 *   EVT_PROC_NEW    fires from ops.init_task (fork + scheduler-attach pass).
 *   EVT_PROC_EXEC   fires from tp_btf/sched_process_exec.
 *   EVT_SAMPLE      fires from ops.stopping after EVT_STOPPING.
 * These three carry the standard 24-byte header so attribution is
 * stateless — every event identifies its own subject. See
 * docs/superpowers/specs/2026-05-12-stack-sample-thread-annotation-design.md.
 */
enum scx_invariant_event_type {
    EVT_RUNNING     = 0x0100,
    EVT_STOPPING    = 0x0101,
    EVT_RUNNABLE    = 0x0102,
    EVT_QUIESCENT   = 0x0103,
    EVT_PROC_NEW    = 0x0104,
    EVT_PROC_EXEC   = 0x0105,
    EVT_SAMPLE      = 0x0106,
};

#define FLAG_MIGRATED       (1 << 0)
#define FLAG_SYNC_WAKEUP    (1 << 1)
#define FLAG_VOLUNTARY      (1 << 2)

/*
 * STACK_DEPTH_MAX caps the per-quantum user-stack walk in
 * invariant_stopping. 16 frames is enough for hot-stack annotation
 * (two-three frames are surfaced in the wakeup graph; 16 keeps a
 * deeper tail available for the per-thread expander in the HTML
 * report). Frame-pointer-less binaries are out of scope for v1 of
 * this collector — see design §10.
 */
#define STACK_DEPTH_MAX 16

struct scx_invariant_event {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 cpu;
    u16 event_type;
    u16 flags;
};

/*
 * cpu_perf and pmc_* are RESERVED-ZERO in the current recorder.
 *
 * The fields remain in the v2 ABI for stability — struct sizes
 * (88 B for both evt_running and evt_stopping) and field offsets
 * are frozen, so existing v2 readers and existing v2 traces keep
 * working unchanged. Writers MUST emit zeros and readers SHOULD
 * ignore them unless a future task explicitly reclaims the slots
 * with documented semantics.
 *
 * Historical context: these slots once held a per-quantum PMU
 * profile (instructions / cycles / L2 refills / backend-stall
 * cycles) plus a normalized [1, SCX_CPUPERF_ONE] frequency hint
 * (cpu_perf). PMU collection was removed when the project focus
 * shifted to waker-wakee topology. See work/changelog.md
 * 2026-05-11 "reserved-zero PMU cleanup".
 */
struct evt_running {
    struct scx_invariant_event hdr;
    u64 runq_wait_ns;
    u32 waker_pid;
    u32 waker_tgid;
    u16 waker_flags;
    u16 cpu_perf;            /* RESERVED-ZERO; see comment above */
    s32 prev_cpu;
    u64 wake_flags;
    /* pmc_* below are RESERVED-ZERO; see comment above */
    u64 pmc_instructions;
    u64 pmc_cycles;
    u64 pmc_l2_misses;
    u64 pmc_stall_backend;
};

struct evt_stopping {
    struct scx_invariant_event hdr;
    u64 runtime_ns;
    /* pmc_* below are RESERVED-ZERO; see comment above evt_running */
    u64 pmc_instructions;
    u64 pmc_cycles;
    u64 pmc_l2_misses;
    u64 pmc_stall_backend;
    u64 slice_consumed_ns;
    u64 slice_allocated_ns;
    u8  voluntary;
    u8  pad[7];
};

struct evt_runnable {
    struct scx_invariant_event hdr;
    u64 sleep_duration_ns;
    u32 enq_flags;
    u32 pad;
};

struct evt_quiescent {
    struct scx_invariant_event hdr;
    u32 deq_flags;
    u32 pad;
};

/*
 * Per-task identity notification.
 *
 * Emitted from ops.init_task on both the fork path and the
 * scheduler-attach synchronous pass over existing tasks. comm is
 * read straight out of the in-kernel task_struct (verified BTF
 * pointer; sleepable program) and is authoritative. Userspace MUST
 * NOT prefer /proc/<pid>/comm over this value.
 *
 * 56 B total; trailing pad keeps 8-byte alignment.
 */
struct evt_proc_new {
    struct scx_invariant_event hdr;   /* event_type = EVT_PROC_NEW */
    u32 ppid;                          /* real_parent->tgid */
    u8  comm[16];
    u32 pad[3];
};

/*
 * Exec notification.
 *
 * Carries the post-exec in-kernel `task->comm` so the analyzer's
 * proc table reflects the new identity. EVT_PROC_NEW captures comm
 * at fork time, which is the *pre*-exec value inherited from the
 * parent (Linux `clone()` copies task->comm into the child). For a
 * fork+exec child the kernel rewrites comm during execve, and
 * without this refresh the analyzer renders that PID under its
 * stale parent comm forever — e.g. a workload spawned by
 * `scx_invariant record -- <cmd>` shows up as "scx_invariant"
 * instead of "<cmd>" in the wakeup graph. See work/changelog.md
 * 2026-05-12 (post-exec comm refresh).
 *
 * The userspace recorder also re-reads /proc/<pid>/{maps, cmdline}
 * on receipt because the new image invalidates the prior maps
 * snapshot — same dispatch site, separate concern.
 *
 * 40 B total (24 hdr + 16 comm). 8-byte aligned, no pad.
 *
 * Backward compatibility: the analyzer accepts both 40 B (this
 * layout) and 24 B (pre-2026-05-12 layout, no comm) for
 * EVT_PROC_EXEC. Old traces decode with no post-exec comm update,
 * which is the correct historical interpretation.
 */
struct evt_proc_exec {
    struct scx_invariant_event hdr;   /* event_type = EVT_PROC_EXEC */
    u8 comm[16];
};

/*
 * Per-quantum user-stack sample, BPF→userspace wire format.
 *
 * BPF cannot use bpf_get_stackid() from sched_ext struct_ops
 * callbacks — the kernel only exposes that helper to programs whose
 * context provides pt_regs (kprobe/perf_event/tracepoint/raw_tp);
 * sched_ext struct_ops resolves helpers via bpf_base_func_proto in
 * kernel/sched/ext.c which does NOT include bpf_get_stackid_proto.
 * What IS available is bpf_get_task_stack(task, buf, size, flags),
 * which writes the IP[] array directly into a buffer with no
 * kernel-side dedup.
 *
 * Wire layout (160 B):
 *   hdr(24) + walk_ret:s32(4) + pad:u32(4) + ip[16]:u64(128).
 *
 * walk_ret is the raw bpf_get_task_stack() return: a non-negative
 * byte count when successful (depth = walk_ret / sizeof(u64)), a
 * negative -errno on failure (preserved as-is so the analyzer can
 * surface per-PID failed-walk counters per design §8).
 *
 * Disk layout for EVT_SAMPLE is 32 B:
 *   hdr(24) + stack_id:s32(4) + pad:u32(4).
 * The recorder hot path hashes the IP[] array, allocates a
 * per-trace stack_id, and writes the 32 B disk record. The
 * stack-id table is dumped to the ProcStacks (0x0005) section at
 * finalize. Negative walk_ret values are written to disk as
 * stack_id == walk_ret (negative, no IPs).
 */
struct evt_sample {
    struct scx_invariant_event hdr;   /* event_type = EVT_SAMPLE */
    s32 walk_ret;
    u32 pad;
    u64 ip[STACK_DEPTH_MAX];
};

#endif /* __INTF_H */
