#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/* Task-local storage */
struct task_ctx {
	u64 last_running_at;
	u64 last_stopping_at;
	u64 last_quiescent_at;
	u64 pmc_instructions_start;
	u64 pmc_cycles_start;
	u64 pmc_l2_misses_start;
	u64 pmc_stall_backend_start;
	u64 slice_at_start;
	s32 last_cpu;
	u32 waker_pid;
	u32 waker_tgid;
	u16 waker_flags;
	s16 waker_prev_cpu;
	u64 waker_wake_flags;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_map SEC(".maps");

/* 6 partitioned ring buffers (32MB each) */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 32 * 1024 * 1024);
} events_rb_0 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 32 * 1024 * 1024);
} events_rb_1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 32 * 1024 * 1024);
} events_rb_2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 32 * 1024 * 1024);
} events_rb_3 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 32 * 1024 * 1024);
} events_rb_4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 32 * 1024 * 1024);
} events_rb_5 SEC(".maps");

/* Drop counter */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
} drop_counter SEC(".maps");

static __always_inline void *rb_reserve(u32 cpu, u64 size)
{
	if ((cpu % 6) == 0)
		return bpf_ringbuf_reserve(&events_rb_0, size, 0);
	else if ((cpu % 6) == 1)
		return bpf_ringbuf_reserve(&events_rb_1, size, 0);
	else if ((cpu % 6) == 2)
		return bpf_ringbuf_reserve(&events_rb_2, size, 0);
	else if ((cpu % 6) == 3)
		return bpf_ringbuf_reserve(&events_rb_3, size, 0);
	else if ((cpu % 6) == 4)
		return bpf_ringbuf_reserve(&events_rb_4, size, 0);
	else
		return bpf_ringbuf_reserve(&events_rb_5, size, 0);
}

/*
 * Submit event without waking the userspace consumer. At 1M+ events/sec,
 * per-event wakeup IPIs would dominate overhead. Instead, userspace polls
 * on a 1ms timer (ring_buffer__poll with timeout), so events are picked
 * up within 1ms without any notification cost.
 */
static __always_inline void rb_submit(void *evt)
{
	bpf_ringbuf_submit(evt, BPF_RB_NO_WAKEUP);
}

static __always_inline void rb_drop_inc(void)
{
	u32 key = 0;
	u64 *cnt = bpf_map_lookup_elem(&drop_counter, &key);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
}

void BPF_STRUCT_OPS(invariant_enqueue, struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(invariant_running, struct task_struct *p)
{
	struct task_ctx *tctx = bpf_task_storage_get(
		&task_ctx_map, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return;

	u64 now = scx_bpf_now();
	s32 cpu = scx_bpf_task_cpu(p);
	bool migrated = (tctx->last_cpu >= 0 && tctx->last_cpu != cpu);

	struct evt_running *evt = rb_reserve(cpu, sizeof(*evt));
	if (evt) {
		evt->hdr.timestamp_ns = now;
		evt->hdr.pid = p->pid;
		evt->hdr.tgid = p->tgid;
		evt->hdr.cpu = cpu;
		evt->hdr.event_type = EVT_RUNNING;
		evt->hdr.flags = migrated ? FLAG_MIGRATED : 0;
		evt->runq_wait_ns = (p->scx.runnable_at > 0) ?
				     (now - p->scx.runnable_at) : 0;
		/* Waker fields zeroed for now (Task 4 adds select_cpu) */
		evt->waker_pid = 0;
		evt->waker_tgid = 0;
		evt->waker_flags = 0;
		evt->cpu_perf = 0;
		evt->prev_cpu = -1;
		evt->wake_flags = 0;
		/* PMU fields zeroed for now (Task 5 adds perf counters) */
		evt->pmc_instructions = 0;
		evt->pmc_cycles = 0;
		evt->pmc_l2_misses = 0;
		evt->pmc_stall_backend = 0;
		rb_submit(evt);
	} else {
		rb_drop_inc();
	}

	tctx->last_running_at = now;
	tctx->last_cpu = cpu;
	tctx->slice_at_start = p->scx.slice;
}

void BPF_STRUCT_OPS(invariant_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_map, p, 0, 0);
	if (!tctx)
		return;

	u64 now = scx_bpf_now();
	s32 cpu = scx_bpf_task_cpu(p);
	u64 runtime = now - tctx->last_running_at;

	struct evt_stopping *evt = rb_reserve(cpu, sizeof(*evt));
	if (evt) {
		evt->hdr.timestamp_ns = now;
		evt->hdr.pid = p->pid;
		evt->hdr.tgid = p->tgid;
		evt->hdr.cpu = cpu;
		evt->hdr.event_type = EVT_STOPPING;
		evt->hdr.flags = runnable ? 0 : FLAG_VOLUNTARY;
		evt->runtime_ns = runtime;
		/* PMU deltas zeroed for now */
		evt->pmc_instructions = 0;
		evt->pmc_cycles = 0;
		evt->pmc_l2_misses = 0;
		evt->pmc_stall_backend = 0;
		evt->slice_allocated_ns = tctx->slice_at_start;
		evt->slice_consumed_ns = tctx->slice_at_start - p->scx.slice;
		evt->voluntary = runnable ? 0 : 1;
		rb_submit(evt);
	} else {
		rb_drop_inc();
	}

	tctx->last_stopping_at = now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(invariant_init)
{
	return 0;
}

void BPF_STRUCT_OPS(invariant_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(invariant_ops,
	       .enqueue   = (void *)invariant_enqueue,
	       .running   = (void *)invariant_running,
	       .stopping  = (void *)invariant_stopping,
	       .init      = (void *)invariant_init,
	       .exit      = (void *)invariant_exit,
	       .flags     = SCX_OPS_ENQ_LAST | SCX_OPS_ENQ_EXITING,
	       .timeout_ms = 5000,
	       .name      = "invariant");
