#include <scx/common.bpf.h>
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

/*
 * PMU perf-event arrays (Task 5 of scx_invariant PLAN.md).
 *
 * One array per logical counter, indexed by cpu_id. Userspace populates
 * each slot via bpf_map__update_elem with a perf_event fd opened in
 * system-wide CPU-pinned mode (pid=-1, cpu=N). BPF reads with
 * bpf_perf_event_read_value(); when a slot is unset (open failed for that
 * cpu) the helper returns -ENOENT and read_pmc() returns 0 — the field
 * lands in the trace as 0 rather than refusing to record.
 *
 * max_entries is set to a generous static upper bound (1024) so the map
 * fits any host this scheduler is likely to run on without negotiating
 * sizes with userspace at load time. Slots beyond nr_cpus stay unset.
 */
#define SCX_INVARIANT_MAX_CPUS 1024

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(int));
	__uint(max_entries, SCX_INVARIANT_MAX_CPUS);
} pmu_instructions SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(int));
	__uint(max_entries, SCX_INVARIANT_MAX_CPUS);
} pmu_cycles SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(int));
	__uint(max_entries, SCX_INVARIANT_MAX_CPUS);
} pmu_l2_misses SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(int));
	__uint(max_entries, SCX_INVARIANT_MAX_CPUS);
} pmu_stall_backend SEC(".maps");

/*
 * Read a single PMU counter for @cpu via the given perf-event-array map.
 *
 * Returns 0 when the slot is unset, the helper rejects the read (e.g.
 * counter not enabled, multiplexing pause), or any other failure. Callers
 * pair this with a saved start value, so 0 simply yields a delta of zero
 * which the reader interprets as "no PMU data this quantum" — same as
 * the pre-Task-5 placeholder behavior.
 *
 * We deliberately ignore v.enabled / v.running for now. With four counters
 * per CPU we expect to fit on every PMU we care about without
 * multiplexing; if measurement later shows divergence we can scale by
 * (enabled / running) without changing the on-disk format.
 */
static __always_inline u64 read_pmc(void *map, s32 cpu)
{
	struct bpf_perf_event_value v = {};

	if (bpf_perf_event_read_value(map, cpu, &v, sizeof(v)) < 0)
		return 0;
	return v.counter;
}

/*
 * Saturating subtraction for per-quantum PMC deltas.
 *
 * Both `end` and `start` are u64 perf-counter samples from `read_pmc()`.
 * Two failure modes can make `end < start` and turn a naive `end - start`
 * into a near-UINT64_MAX wraparound:
 *
 *   1. The counter was readable at running() time (start > 0) but the
 *      stopping() read failed (`end == 0`). ARM PMU power-state
 *      transitions, transient -EBUSY from event multiplexing, or any
 *      kfunc-returns-negative path triggers this. The reverse
 *      (start == 0, end > 0) is a documented one-off; this direction
 *      is the catastrophic one — a single underflowed sample dominates
 *      any aggregator over the whole trace.
 *
 *   2. running() was skipped for this quantum while stopping() fires
 *      (kernel SCX_TASK_QUEUED pairing isn't airtight under hotplug /
 *      fork-into-SCX races). `tctx->pmc_*_start` then carries values
 *      from a *previous* quantum, which are typically smaller than the
 *      current `end` — so this case usually produces an inflated-but-
 *      positive delta rather than an underflow. Sat-sub doesn't fully
 *      neutralize it; a generation-bit guard would. We accept that
 *      higher-order bug for now and just kill the underflow.
 *
 * Returns 0 when end < start, matching the start-side "no PMU data this
 * quantum" semantics. The reader still sees zero counters as "missing";
 * that's better than poisoned aggregates.
 */
static __always_inline u64 sat_sub(u64 end, u64 start)
{
	return end >= start ? end - start : 0;
}

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

	/*
	 * Snapshot per-task PMU baselines for the quantum (Task 5).
	 *
	 * The snapshots land in task storage (tctx->pmc_*_start), where
	 * invariant_stopping pairs them against end-of-quantum reads to
	 * compute the per-quantum delta written into evt_stopping.
	 *
	 * We deliberately do NOT publish these raw start-of-quantum
	 * snapshots into evt_running's pmc_* slots. Reasoning:
	 *   1. A lifetime CPU-wide counter snapshot at one arbitrary
	 *      moment is not standalone meaningful — it only gains
	 *      meaning when diffed against another snapshot on the same
	 *      CPU, which is precisely what the matching evt_stopping
	 *      delta already provides.
	 *   2. evt_running.pmc_* and evt_stopping.pmc_* share field names
	 *      across the on-disk format. Putting different physical
	 *      units in identically-named fields is a footgun: any
	 *      future aggregator that iterates all events and sums
	 *      pmc_instructions would silently double-count
	 *      (lifetime totals + per-quantum deltas).
	 * The slots stay in evt_running for format-stability (no payload
	 * size change vs. older traces) but are written as zero. cpu_perf
	 * IS standalone meaningful (it's a normalized [1, SCX_CPUPERF_ONE]
	 * frequency-state hint) and stays populated.
	 *
	 * Read happens before rb_reserve so the start values land in
	 * task storage even if the ringbuf reservation fails — otherwise
	 * a single drop here would desync the next stopping callback's
	 * delta computation. read_pmc() returns 0 when a counter slot is
	 * unset; the corresponding stopping delta then reads as 0 too.
	 */
	u64 ins_start    = read_pmc(&pmu_instructions, cpu);
	u64 cyc_start    = read_pmc(&pmu_cycles,       cpu);
	u64 l2m_start    = read_pmc(&pmu_l2_misses,    cpu);
	u64 stall_start  = read_pmc(&pmu_stall_backend, cpu);

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
		/*
		 * scx_bpf_cpuperf_cur() returns u32 in [1, SCX_CPUPERF_ONE]
		 * where SCX_CPUPERF_ONE == SCHED_CAPACITY_SCALE == 1024 on
		 * every supported config (include/linux/sched.h:453,458).
		 * The full range fits in u16, so the cast is value-preserving;
		 * we keep the trace-format slot as u16 per intf.h.
		 */
		evt->cpu_perf = (u16)scx_bpf_cpuperf_cur(cpu);
		evt->prev_cpu = first_run ? -1 : tctx->last_cpu;
		evt->wake_flags = tctx->waker_wake_flags;
		/*
		 * Reserved-zero per the contract above. Real per-quantum
		 * counter values live in evt_stopping. Do not start
		 * populating these without re-reading the comment block at
		 * the top of this function.
		 */
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
	tctx->pmc_instructions_start  = ins_start;
	tctx->pmc_cycles_start        = cyc_start;
	tctx->pmc_l2_misses_start     = l2m_start;
	tctx->pmc_stall_backend_start = stall_start;
	/* Clear waker fields to avoid stale data on next schedule */
	tctx->waker_pid = 0;
	tctx->waker_tgid = 0;
	tctx->waker_flags = 0;
	tctx->waker_wake_flags = 0;
}

/*
 * No-op for now. Reserved hook — we'll add work here once we figure out
 * what's actually worth recording at a tick boundary. When real work is
 * added, gate it on is_target_task(p) like the sibling callbacks; an
 * empty body has nothing to short-circuit, so gating here today would
 * just be a kfunc chain in spawn mode for a discarded bool.
 */
void BPF_STRUCT_OPS(invariant_tick, struct task_struct *p)
{
	(void)p;
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

	/*
	 * Per-quantum PMU deltas (Task 5). u64 counter wraparound from
	 * forward progress is not a practical concern over a single
	 * scheduling quantum.
	 *
	 * We read system-wide CPU-pinned counters: on a single CPU, no
	 * other task can run between this task's running and stopping
	 * callbacks, so end - start equals the work this task performed
	 * (plus any kernel-mode work — interrupts, softirqs — observed on
	 * that CPU during the quantum, which is the standard accuracy /
	 * cost tradeoff and acceptable per work/task.md "Approach A").
	 *
	 * sat_sub() handles the failure-mode cases where a naive
	 * subtraction would underflow:
	 *   - counter readable at running(), unreadable at stopping()
	 *     (perf_event_open success at startup but transient kfunc
	 *      failure now: pause, power state, multiplexing eviction);
	 *   - running() skipped this quantum while stopping() fires
	 *     (kernel SCX_TASK_QUEUED pairing race), leaving
	 *     tctx->pmc_*_start stale from a prior quantum.
	 * See sat_sub()'s comment for the full enumeration. The "unset at
	 * start, available at end" case is bounded by counter lifetime
	 * size and lands as a one-off oversized delta — acceptable.
	 */
	u64 ins_end   = read_pmc(&pmu_instructions,  cpu);
	u64 cyc_end   = read_pmc(&pmu_cycles,        cpu);
	u64 l2m_end   = read_pmc(&pmu_l2_misses,     cpu);
	u64 stall_end = read_pmc(&pmu_stall_backend, cpu);

	struct evt_stopping *evt = rb_reserve(cpu, sizeof(*evt));
	if (evt) {
		evt->hdr.timestamp_ns = now;
		evt->hdr.pid = p->pid;
		evt->hdr.tgid = p->tgid;
		evt->hdr.cpu = cpu;
		evt->hdr.event_type = EVT_STOPPING;
		evt->hdr.flags = runnable ? 0 : FLAG_VOLUNTARY;
		evt->runtime_ns = runtime;
		evt->pmc_instructions  = sat_sub(ins_end,   tctx->pmc_instructions_start);
		evt->pmc_cycles        = sat_sub(cyc_end,   tctx->pmc_cycles_start);
		evt->pmc_l2_misses     = sat_sub(l2m_end,   tctx->pmc_l2_misses_start);
		evt->pmc_stall_backend = sat_sub(stall_end, tctx->pmc_stall_backend_start);
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
	       .tick      = (void *)invariant_tick,
	       .stopping  = (void *)invariant_stopping,
	       .quiescent = (void *)invariant_quiescent,
	       .init      = (void *)invariant_init,
	       .exit      = (void *)invariant_exit,
	       .flags     = SCX_OPS_ENQ_LAST | SCX_OPS_ENQ_EXITING,
	       .timeout_ms = 5000,
	       .name      = "invariant");
