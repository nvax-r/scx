#include <scx/common.bpf.h>
#include <bpf_experimental.h>
#include "intf.h"
#include <lib/cleanup.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * Cgroup filtering plumbing (Task 3 of scx_invariant PLAN.md).
 *
 * cgroup_filtering: master gate. If false, is_target_task always returns
 *                   true, so system-wide mode remains the default.
 * target_cgid:      inode of the target cgroupv2 directory. Resolved to a
 *                   struct cgroup * on each callback via bpf_cgroup_from_id().
 *
 * We do NOT cache the cgroup pointer across callbacks: sched_ext struct_ops
 * programs have no clean place to stash a ref-counted cgroup ptr. The
 * three-helper cost (from_id + under_cgroup + release-via-__free) is
 * acceptable on the gated path.
 *
 * __free(cgroup) invokes bpf_cgroup_release on scope exit, handling NULL
 * safely per DEFINE_FREE in lib/cleanup.bpf.h.
 */
const volatile bool cgroup_filtering = false;
const volatile u64 target_cgid = 0;

extern long bpf_task_under_cgroup(struct task_struct *task, struct cgroup *ancestor) __ksym;

static __always_inline bool is_target_task(struct task_struct *p)
{
	if (!cgroup_filtering)
		return true;
	if (!p)
		return false;

	struct cgroup *cg __free(cgroup) = bpf_cgroup_from_id(target_cgid);
	if (!cg)
		return false;

	return bpf_task_under_cgroup(p, cg) != 0;
}

/* Task-local storage */
struct task_ctx {
	u64 last_running_at;
	u64 last_stopping_at;
	u64 last_quiescent_at;
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

/*
 * Process-only waker attribution filter.
 *
 * `current` in ops.select_cpu() is only a candidate waker. select_task_rq_scx
 * is reached from try_to_wake_up(), which can fire from many non-process
 * contexts: hardirq/softirq/NMI handlers, the idle task draining deferred
 * wake work, kworkers, ksoftirqd, IO workers, etc. Recording any of those
 * as a process waker fabricates fake process-to-process edges in the wakeup
 * graph. The correct behavior is to emit no waker (waker_pid = 0) when the
 * candidate is not a normal process running in task context — readers
 * already treat a zero waker_pid as "no edge".
 *
 * This is the scx-only filter: we do not try to recover the original waker
 * for queued/deferred wakeups (those go through wake-list drains on a
 * different CPU and lose process causality entirely). Such wakeups are left
 * as unknown rather than attributed to whatever happens to be drain-side
 * `current`.
 *
 * The IRQ/softirq/NMI helpers are reliable on x86 and arm64 only, which
 * covers our target machines and matches scx_lavd's usage pattern.
 */
static __always_inline void clear_waker(struct task_ctx *tctx)
{
	tctx->waker_pid = 0;
	tctx->waker_tgid = 0;
	tctx->waker_flags = 0;
	tctx->waker_wake_flags = 0;
}

static __always_inline bool is_process_waker(struct task_struct *waker)
{
	if (!waker)
		return false;

	if (bpf_in_hardirq() || bpf_in_serving_softirq() || bpf_in_nmi())
		return false;

	if (waker->pid == 0 || waker->tgid == 0)
		return false;

	if (waker->flags & (PF_IDLE | PF_KTHREAD | PF_WQ_WORKER | PF_IO_WORKER))
		return false;

	return true;
}

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

s32 BPF_STRUCT_OPS(invariant_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	/* Drop waker attribution for tasks outside the target cgroup.
	 * Scheduling decision is preserved: we still return prev_cpu below. */
	if (!is_target_task(p))
		return prev_cpu;

	struct task_ctx *tctx = bpf_task_storage_get(
		&task_ctx_map, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return prev_cpu;

	struct task_struct *waker = bpf_get_current_task_btf();
	if (!is_process_waker(waker)) {
		clear_waker(tctx);
		return prev_cpu;
	}

	tctx->waker_pid = waker->pid;
	tctx->waker_tgid = waker->tgid;
	tctx->waker_wake_flags = wake_flags;

	return prev_cpu;
}

void BPF_STRUCT_OPS(invariant_enqueue, struct task_struct *p, u64 enq_flags)
{
	/* Scheduling operation — intentionally NOT cgroup-gated. Gating here
	 * would drop tasks outside the target cgroup from being dispatched. */
	scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(invariant_running, struct task_struct *p)
{
	if (!is_target_task(p))
		return;

	struct task_ctx *tctx = bpf_task_storage_get(
		&task_ctx_map, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return;

	u64 now = scx_bpf_now();
	s32 cpu = scx_bpf_task_cpu(p);
	bool first_run = (tctx->last_running_at == 0);
	bool migrated = !first_run && (tctx->last_cpu != cpu);

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
		evt->waker_pid = tctx->waker_pid;
		evt->waker_tgid = tctx->waker_tgid;
		evt->waker_flags = tctx->waker_flags;
		evt->prev_cpu = first_run ? -1 : tctx->last_cpu;
		evt->wake_flags = tctx->waker_wake_flags;
		/*
		 * cpu_perf and pmc_* are RESERVED-ZERO in the current
		 * recorder. The slots remain in v2 for ABI stability
		 * (struct size unchanged); writers MUST emit zeros and
		 * readers SHOULD ignore them. See src/bpf/intf.h for the
		 * full reserved-zero contract.
		 */
		evt->cpu_perf          = 0;
		evt->pmc_instructions  = 0;
		evt->pmc_cycles        = 0;
		evt->pmc_l2_misses     = 0;
		evt->pmc_stall_backend = 0;
		rb_submit(evt);
	} else {
		rb_drop_inc();
	}

	tctx->last_running_at = now;
	tctx->last_cpu = cpu;
	tctx->slice_at_start = p->scx.slice;
	/* Clear waker fields to avoid stale data on next schedule */
	clear_waker(tctx);
}

void BPF_STRUCT_OPS(invariant_stopping, struct task_struct *p, bool runnable)
{
	if (!is_target_task(p))
		return;

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
		/*
		 * pmc_* are RESERVED-ZERO in the current recorder. Slots
		 * remain in v2 for ABI stability (struct size unchanged);
		 * writers MUST emit zeros and readers SHOULD ignore them.
		 * See src/bpf/intf.h for the full reserved-zero contract.
		 */
		evt->pmc_instructions  = 0;
		evt->pmc_cycles        = 0;
		evt->pmc_l2_misses     = 0;
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

void BPF_STRUCT_OPS(invariant_runnable, struct task_struct *p, u64 enq_flags)
{
	if (!is_target_task(p))
		return;

	struct task_ctx *tctx = bpf_task_storage_get(
		&task_ctx_map, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return;

	u64 now = scx_bpf_now();
	s32 cpu = scx_bpf_task_cpu(p);
	u64 sleep_duration = 0;

	if (tctx->last_quiescent_at > 0)
		sleep_duration = now - tctx->last_quiescent_at;

	struct evt_runnable *evt = rb_reserve(cpu, sizeof(*evt));
	if (evt) {
		evt->hdr.timestamp_ns = now;
		evt->hdr.pid = p->pid;
		evt->hdr.tgid = p->tgid;
		evt->hdr.cpu = cpu;
		evt->hdr.event_type = EVT_RUNNABLE;
		evt->hdr.flags = 0;
		evt->sleep_duration_ns = sleep_duration;
		evt->enq_flags = (u32)enq_flags;
		evt->pad = 0;
		rb_submit(evt);
	} else {
		rb_drop_inc();
	}
}

void BPF_STRUCT_OPS(invariant_quiescent, struct task_struct *p, u64 deq_flags)
{
	if (!is_target_task(p))
		return;

	struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_map, p, 0, 0);
	if (!tctx)
		return;

	u64 now = scx_bpf_now();
	s32 cpu = scx_bpf_task_cpu(p);

	tctx->last_quiescent_at = now;

	struct evt_quiescent *evt = rb_reserve(cpu, sizeof(*evt));
	if (evt) {
		evt->hdr.timestamp_ns = now;
		evt->hdr.pid = p->pid;
		evt->hdr.tgid = p->tgid;
		evt->hdr.cpu = cpu;
		evt->hdr.event_type = EVT_QUIESCENT;
		evt->hdr.flags = 0;
		evt->deq_flags = (u32)deq_flags;
		evt->pad = 0;
		rb_submit(evt);
	} else {
		rb_drop_inc();
	}
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
	       .select_cpu = (void *)invariant_select_cpu,
	       .enqueue   = (void *)invariant_enqueue,
	       .runnable  = (void *)invariant_runnable,
	       .running   = (void *)invariant_running,
	       .stopping  = (void *)invariant_stopping,
	       .quiescent = (void *)invariant_quiescent,
	       .init      = (void *)invariant_init,
	       .exit      = (void *)invariant_exit,
	       .flags     = SCX_OPS_ENQ_LAST | SCX_OPS_ENQ_EXITING,
	       .timeout_ms = 5000,
	       .name      = "invariant");
