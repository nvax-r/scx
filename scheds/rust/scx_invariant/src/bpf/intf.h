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
 * section IDs (SECTION_* in src/output.rs, occupying 0x0001..0x0003).
 * This is the v2 .scxi format invariant — see PLAN.md §5/§6/§11.
 * Do not assign event IDs in the 0x0001..0x00FF range.
 */
enum scx_invariant_event_type {
    EVT_RUNNING     = 0x0100,
    EVT_STOPPING    = 0x0101,
    EVT_RUNNABLE    = 0x0102,
    EVT_QUIESCENT   = 0x0103,
};

#define FLAG_MIGRATED       (1 << 0)
#define FLAG_SYNC_WAKEUP    (1 << 1)
#define FLAG_VOLUNTARY      (1 << 2)

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

#endif /* __INTF_H */
