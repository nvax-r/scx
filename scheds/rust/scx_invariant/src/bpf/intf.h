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

enum scx_invariant_event_type {
    EVT_RUNNING     = 1,
    EVT_STOPPING    = 2,
    EVT_RUNNABLE    = 3,
    EVT_QUIESCENT   = 4,
    EVT_TICK        = 5,
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

struct evt_running {
    struct scx_invariant_event hdr;
    u64 runq_wait_ns;
    u32 waker_pid;
    u32 waker_tgid;
    u16 waker_flags;
    u16 cpu_perf;
    s32 prev_cpu;
    u64 wake_flags;
    u64 pmc_instructions;
    u64 pmc_cycles;
    u64 pmc_l2_misses;
    u64 pmc_stall_backend;
};

struct evt_stopping {
    struct scx_invariant_event hdr;
    u64 runtime_ns;
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

struct evt_tick {
    struct scx_invariant_event hdr;
    u64 pmc_instructions;
    u64 pmc_cycles;
    u64 pmc_l2_misses;
    u64 sum_exec_runtime;
    u32 nr_running;
    u32 pad;
};

#endif /* __INTF_H */
