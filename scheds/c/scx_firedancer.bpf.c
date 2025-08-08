/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple scheduler for firedancer processes.
 *
 * WIP
 * pseudo code for how sched ext runs
 */
#include <scx/common.bpf.h>
#include "scx_firedancer.h"

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
	__uint(max_entries, 5);  /* [firedancer, other, select_cpu_firedancer, select_cpu_other, scheduler_descheduled] */
} stats SEC(".maps");

/*
 * The map containing tasks that are enqueued in user space from the kernel.
 *
 * This map is drained by the user space scheduler.
 */
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, MAX_ENQUEUED_TASKS);
	__type(value, struct scx_fd_enqueued_task);
} enqueued SEC(".maps");

/*
 * The map containing tasks that are dispatched to the kernel from user space.
 *
 * Drained by the kernel in userland_dispatch().
 */
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, MAX_ENQUEUED_TASKS);
	__type(value, s32);
} dispatched SEC(".maps");

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
	// TODO: classify based on user
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
	s32 cpu;
	bool direct = false;
	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &direct);

	if (direct) {
		if (is_firedancer_task(p)) {
			stat_inc(2);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		} else {
			stat_inc(3);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		}
	}

	return cpu;
}

static void enqueue_task_in_user_space(struct task_struct *p, u64 enq_flags)
{
	struct scx_fd_enqueued_task task = {};

	task.pid = p->pid;
	task.sum_exec_runtime = p->se.sum_exec_runtime;
	task.weight = p->scx.weight;

	if (bpf_map_push_elem(&enqueued, &task, 0)) {
		bpf_printk("failed to enqueue IN USER SPACE, task: %s", p->comm);
		scx_bpf_dsq_insert(p, OTHER_DSQ, SCX_SLICE_DFL, enq_flags);
	}
}

void BPF_STRUCT_OPS(firedancer_enqueue, struct task_struct *p, u64 enq_flags)
{
	if (is_firedancer_task(p)) {
		enqueue_task_in_user_space(p, enq_flags);
		stat_inc(0);  /* count firedancer tasks */
	} else {
		scx_bpf_dsq_insert(p, OTHER_DSQ, SCX_SLICE_DFL, enq_flags);
		stat_inc(1);  /* count other tasks */
	}
}

void BPF_STRUCT_OPS(firedancer_dispatch, s32 cpu, struct task_struct *prev)
{
	bpf_repeat(MAX_ENQUEUED_TASKS) {
		s32 pid;
		struct task_struct *p;
		if (bpf_map_pop_elem(&dispatched, &pid))
			break;
		p = bpf_task_from_pid(pid);
		if (!p) /* task exited by time we got around to dispatching it which is normal */
			continue;
		scx_bpf_dsq_insert(p, FIREDANCER_DSQ, SCX_SLICE_DFL, 0);
		bpf_task_release(p);
	}

	if (scx_bpf_dsq_move_to_local(FIREDANCER_DSQ))
		return;

	if (scx_bpf_dsq_move_to_local(OTHER_DSQ))
		return;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(firedancer_init)
{
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