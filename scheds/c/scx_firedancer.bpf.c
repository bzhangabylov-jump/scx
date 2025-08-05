/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple scheduler for firedancer processes.
 *
 * This scheduler reserves CPUs 0-3 for firedancer processes and ensures
 * they get priority over other tasks.
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

/* Firedancer-specific configuration */
#define FIREDANCER_CPU_MASK    0xF      /* CPUs 0-3 */
#define FIREDANCER_DSQ         0        /* Custom DSQ for Firedancer tasks */
#define OTHER_DSQ              1        /* Custom DSQ for other tasks */

/* Statistics tracking */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);  /* [firedancer, other] */
} stats SEC(".maps");

UEI_DEFINE(uei);

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

/* Helper function to check if a task is a Firedancer task */
static bool is_firedancer_task(struct task_struct *p)
{
	/* Benchmark tiles */
	if (bpf_strncmp(p->comm, 7, "benchg:") == 0) return true;
	if (bpf_strncmp(p->comm, 7, "benchs:") == 0) return true;
	if (bpf_strncmp(p->comm, 7, "bencho:") == 0) return true;
	if (bpf_strncmp(p->comm, 5, "bank:") == 0) return true;

	/* Core processing tiles */
	if (bpf_strncmp(p->comm, 4, "poh:") == 0) return true;
	if (bpf_strncmp(p->comm, 7, "verify:") == 0) return true;
	if (bpf_strncmp(p->comm, 5, "pack:") == 0) return true;

	/* Network tiles */
	if (bpf_strncmp(p->comm, 5, "quic:") == 0) return true;
	if (bpf_strncmp(p->comm, 4, "net:") == 0) return true;
	if (bpf_strncmp(p->comm, 5, "sock:") == 0) return true;
	if (bpf_strncmp(p->comm, 4, "xdp:") == 0) return true;

	/* Data processing tiles */
	if (bpf_strncmp(p->comm, 6, "dedup:") == 0) return true;
	if (bpf_strncmp(p->comm, 7, "netlnk:") == 0) return true;
	if (bpf_strncmp(p->comm, 7, "resolv:") == 0) return true;
	if (bpf_strncmp(p->comm, 6, "shred:") == 0) return true;
	if (bpf_strncmp(p->comm, 5, "sign:") == 0) return true;
	if (bpf_strncmp(p->comm, 6, "store:") == 0) return true;

	/* Service tiles */
	if (bpf_strncmp(p->comm, 7, "metric:") == 0) return true;
	if (bpf_strncmp(p->comm, 7, "plugin:") == 0) return true;
	if (bpf_strncmp(p->comm, 4, "gui:") == 0) return true;

	/* Other tiles */
	if (bpf_strncmp(p->comm, 7, "bundle:") == 0) return true;
	if (bpf_strncmp(p->comm, 7, "cswtch:") == 0) return true;

	return false;
}

s32 BPF_STRUCT_OPS(firedancer_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	// if (is_firedancer_task(p)) {
	// 	/* Prefer CPUs 0-3 for Firedancer tasks */
	// 	// bool is_idle = false;
	// 	s32 cpu;

	// 	/* First try to find an idle CPU among 0-3 */
	// 	for (cpu = 0; cpu < 4; cpu++) {
	// 		if (scx_bpf_test_and_clear_cpu_idle(cpu))
	// 			return cpu;
	// 	}

	// 	/* If no idle CPU found, prefer CPU 0 */
	// 	return 0;
	// }

	// /* For non-Firedancer tasks, use default selection but avoid CPUs 0-3 if possible */
	// bool is_idle = false;
	// s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

	// /* If selected CPU is in firedancer range and we have other options, try another */
	// if (cpu < 4 && !is_idle) {
	// 	/* Try to find an idle CPU outside the firedancer range */
	// 	s32 nr_cpus = scx_bpf_nr_cpu_ids();
	// 	for (s32 i = 4; i < nr_cpus; i++) {
	// 		if (scx_bpf_test_and_clear_cpu_idle(i))
	// 			return i;
	// 	}
	// }

	// return cpu;
	s32 cpu;
	/* Need to initialize or the BPF verifier will reject the program */
	bool direct = false;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &direct);

	// cut out select_cpu logic for now
	// if (direct)
	// 	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);

	return cpu;
}

void BPF_STRUCT_OPS(firedancer_enqueue, struct task_struct *p, u64 enq_flags)
{
	// scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);

	if (is_firedancer_task(p)) {
		bpf_printk("firedancer_enqueue: %s", p->comm);
		stat_inc(0);  /* count firedancer tasks */
		scx_bpf_dsq_insert(p, FIREDANCER_DSQ, SCX_SLICE_DFL, enq_flags);
	} else {
		// bpf_printk("other_enqueue: %s", p->comm);
		stat_inc(1);  /* count other tasks */
		scx_bpf_dsq_insert(p, OTHER_DSQ, SCX_SLICE_DFL, enq_flags);
	}
}

void BPF_STRUCT_OPS(firedancer_dispatch, s32 cpu, struct task_struct *prev)
{
	if (cpu < 40 && cpu >= 20) {
		bpf_printk("cpu: %d, firedancer_dispatch", cpu);
		/* CPUs 0-3: prioritize firedancer tasks */
		scx_bpf_dsq_move_to_local(FIREDANCER_DSQ);
		/* If no firedancer tasks, allow other tasks to run */
		scx_bpf_dsq_move_to_local(OTHER_DSQ);
	} else {
		/* Other CPUs: prioritize non-firedancer tasks */
		scx_bpf_dsq_move_to_local(OTHER_DSQ);
		/* But also check if there are firedancer tasks that need to run */
	}
}

s32 BPF_STRUCT_OPS_SLEEPABLE(firedancer_init)
{
	// return 0;
	s32 ret;

	/* Create custom DSQs */
	ret = scx_bpf_create_dsq(FIREDANCER_DSQ, -1);
	if (ret)
		return ret;

	ret = scx_bpf_create_dsq(OTHER_DSQ, -1);
	if (ret)
		return ret;

	return 0;
}

void BPF_STRUCT_OPS(firedancer_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(firedancer_ops,
	       .select_cpu		= (void *)firedancer_select_cpu,
	       .enqueue			= (void *)firedancer_enqueue,
	       .dispatch		= (void *)firedancer_dispatch,
	       .init			= (void *)firedancer_init,
	       .exit			= (void *)firedancer_exit,
	       .name			= "firedancer");