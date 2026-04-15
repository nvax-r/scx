#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

void BPF_STRUCT_OPS(invariant_enqueue, struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
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
	       .enqueue    = (void *)invariant_enqueue,
	       .init       = (void *)invariant_init,
	       .exit       = (void *)invariant_exit,
	       .flags      = SCX_OPS_ENQ_LAST | SCX_OPS_ENQ_EXITING,
	       .timeout_ms = 5000,
	       .name       = "invariant");
