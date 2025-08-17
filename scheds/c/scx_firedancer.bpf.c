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
	__uint(max_entries, 6);  /* [firedancer enqueued in US, other, select_cpu_firedancer, select_cpu_other, firedancer enqueued in kernel, firedancer enqueued in kernel (needed for replay)] */
} stats SEC(".maps");

/*
 * Map to track idle status of firedancer processes
 * Key: PID
 * Value: 1 if idle, 0 if active
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(s32));
	__uint(value_size, sizeof(u8));
	__uint(max_entries, 1024);  /* Maximum number of firedancer processes to track */
} fd_idle_status SEC(".maps");

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

/* Leader state: single element array, index 0 => 0/1 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1);
} leader_state SEC(".maps");

/* pid -> preferred cpu mapping (original fixed high performance firedancer topology) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(s32));
	__uint(value_size, sizeof(s32));
	__uint(max_entries, 4096);
} pid_to_cpu SEC(".maps");

/* reserved CPUs (e.g. when leader) */
#define MAX_CPUS 512
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u8));
	__uint(max_entries, MAX_CPUS);
} reserved_cpus SEC(".maps");

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
	// if (bpf_strncmp(p->comm, 7, "netlnk:") == 0) return true;
	if (bpf_strncmp(p->comm, 7, "resolv:") == 0) return true;
	if (bpf_strncmp(p->comm, 6, "shred:") == 0) return true;
	if (bpf_strncmp(p->comm, 5, "sign:") == 0) return true;
	if (bpf_strncmp(p->comm, 6, "store:") == 0) return true;

	/* Service tiles */
	// if (bpf_strncmp(p->comm, 7, "metric:") == 0) return true;
	if (bpf_strncmp(p->comm, 7, "plugin:") == 0) return true;
	if (bpf_strncmp(p->comm, 4, "gui:") == 0) return true;

	/* Other tiles */
	if (bpf_strncmp(p->comm, 7, "bundle:") == 0) return true;
	// if (bpf_strncmp(p->comm, 7, "cswtch:") == 0) return true;

	return false;
}

static __always_inline bool is_leader_now(void)
{
	u32 k = 0;
	u32 *v = bpf_map_lookup_elem(&leader_state, &k);
	return v && (*v != 0);
}

static __always_inline bool cpu_is_reserved(s32 cpu)
{
	u32 idx = (u32)cpu;
	u8 *v = bpf_map_lookup_elem(&reserved_cpus, &idx);
	return v && (*v != 0);
}

static __always_inline s32 get_pid_cpu(s32 pid)
{
	s32 *v = bpf_map_lookup_elem(&pid_to_cpu, &pid);
	return v ? *v : -1;
}

static bool needed_for_replay(struct task_struct *p)
{
	/* Minimal set for replay-critical tiles */
	if (bpf_strncmp(p->comm, 4, "net:") == 0)  return true;
	if (bpf_strncmp(p->comm, 5, "quic:") == 0) return true;
	// TODO: add the rest of the replay-critical tiles
	return false;
}

s32 BPF_STRUCT_OPS(firedancer_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;
	bool direct = false;
	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &direct);
	/* Logic through enqueue/dispatch, for now no select_cpu shortcuts */
	return cpu;
}

static void enqueue_task_in_user_space(struct task_struct *p, u64 enq_flags)
{
	struct scx_fd_enqueued_task task = {};

	task.pid = p->pid;
	task.weight = p->scx.weight; // not needed

	if (bpf_map_push_elem(&enqueued, &task, 0)) {
		bpf_printk("failed to enqueue IN USER SPACE, task: %s", p->comm);
		scx_bpf_dsq_insert(p, OTHER_DSQ, SCX_SLICE_DFL, enq_flags);
	}
}

void BPF_STRUCT_OPS(firedancer_enqueue, struct task_struct *p, u64 enq_flags)
{
	bool leader = is_leader_now();
	if (is_firedancer_task(p)) {
		if (leader) {
			/* Pin to ideal CPU if known */
			s32 target_cpu = get_pid_cpu(p->pid);
			if (target_cpu >= 0)
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u64)target_cpu, SCX_SLICE_DFL, 0);
			else
				scx_bpf_dsq_insert(p, FIREDANCER_DSQ, SCX_SLICE_DFL, 0);
			stat_inc(4);
			return;
		}
		/* Not leader */
		if (needed_for_replay(p)) {
			/* Allow across all cores similar to Agave */
			scx_bpf_dsq_insert(p, OTHER_DSQ, SCX_SLICE_DFL, 0);
			stat_inc(5);
			return;
		}
		/* Hold in userspace */
		enqueue_task_in_user_space(p, enq_flags);
		// TODO: make it so it goes in a map in ebpf instead?
		stat_inc(0);
		return;
	} else {
		/* Agave or other tasks */
		scx_bpf_dsq_insert(p, OTHER_DSQ, SCX_SLICE_DFL, enq_flags);
		stat_inc(1);
		return;
	}
}

void BPF_STRUCT_OPS(firedancer_dispatch, s32 cpu, struct task_struct *prev)
{
	bool leader = is_leader_now();

	/* Drain user-dispatched tasks: insert FD tasks, pin if leader */
	bpf_repeat(MAX_ENQUEUED_TASKS) {
		s32 pid;
		struct task_struct *p;
		if (bpf_map_pop_elem(&dispatched, &pid))
			break;
		p = bpf_task_from_pid(pid);
		if (!p)
			continue;
		if (leader) {
			s32 tcpu = get_pid_cpu(pid);
			if (tcpu >= 0)
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u64)tcpu, SCX_SLICE_DFL, 0);
			else
				scx_bpf_dsq_insert(p, FIREDANCER_DSQ, SCX_SLICE_DFL, 0);
		} else {
			scx_bpf_dsq_insert(p, FIREDANCER_DSQ, SCX_SLICE_DFL, 0);
		}
		bpf_task_release(p);
	}

	if (scx_bpf_dsq_move_to_local(FIREDANCER_DSQ))
		return;

	/* For OTHER tasks, restrict to non-reserved CPUs when leader -> TODO: commented out so kworkers don't time out */
	// if (!leader || !cpu_is_reserved(cpu)) {
		(void)scx_bpf_dsq_move_to_local(OTHER_DSQ);
	// }
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
	       .enqueue		    = (void *)firedancer_enqueue,
	       .dispatch		= (void *)firedancer_dispatch,
	       .init			= (void *)firedancer_init,
	       .exit			= (void *)firedancer_exit,
	       .name			= "firedancer");