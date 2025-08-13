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
	__uint(max_entries, 5);  /* [firedancer enqueued in US, other, select_cpu_firedancer, select_cpu_other, enqueued in kernel] */
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

UEI_DEFINE(uei);

/* !0 for veristat, set during init */
const volatile u32 num_possible_cpus = 64;

const volatile u32 fd_cpu_start = 20;
const volatile u32 fd_cpu_end = 50;

const volatile u32 fd_cpu_start_idle = 20;
const volatile u32 fd_cpu_end_idle = 30;

const volatile u32 IDLE_PCT_THRESHOLD = 85;

static volatile u32 cached_idle_pct = 0;
static volatile u64 counter = 0;
/* Add this map to store system idle percentage */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1);
} system_idle_pct SEC(".maps");

/* Helper to get idle percentage from the map */
static u32 get_system_idle_percentage(void)
{
	counter++;
	if (counter % 100000 == 0) {
		u32 key = 0;
		u32 *pct = bpf_map_lookup_elem(&system_idle_pct, &key);
		if (pct) cached_idle_pct = *pct;
		bpf_printk("getting idle percentage, counter: %llu, cached_idle_pct: %d", counter, cached_idle_pct);
	}
	return cached_idle_pct;
}

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
	// if (bpf_strncmp(p->comm, 5, "bank:") == 0) return true;

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

s32 BPF_STRUCT_OPS(firedancer_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;
	bool direct = false;
	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &direct);

	/* Constrain firedancer tasks to CPUs [fd_cpu_start, fd_cpu_end] */
	if (is_firedancer_task(p)) {
		u32 idle_pct = get_system_idle_percentage();
		u32 cpu_start = fd_cpu_start;
		u32 cpu_end = fd_cpu_end;
		if (idle_pct >= IDLE_PCT_THRESHOLD) {
			cpu_start = fd_cpu_start_idle;
			cpu_end = fd_cpu_end_idle;
		}
		if (cpu < cpu_start || cpu >= cpu_end) {
			if (prev_cpu >= cpu_start && prev_cpu < cpu_end)
				cpu = prev_cpu;
			else
				cpu = cpu_start;
		}
	}
	return cpu;
}

static bool keep_in_kernel(const struct task_struct *p)
{
	return p->nr_cpus_allowed < num_possible_cpus;
}
static void enqueue_task_in_user_space(struct task_struct *p, u64 enq_flags)
{
	struct scx_fd_enqueued_task task = {};

	task.pid = p->pid;
	task.weight = p->scx.weight;

	if (bpf_map_push_elem(&enqueued, &task, 0)) {
		bpf_printk("failed to enqueue IN USER SPACE, task: %s", p->comm);
		scx_bpf_dsq_insert(p, OTHER_DSQ, SCX_SLICE_DFL, enq_flags);
	}
}

void BPF_STRUCT_OPS(firedancer_enqueue, struct task_struct *p, u64 enq_flags)
{
	if (is_firedancer_task(p)) {
		scx_bpf_dsq_insert(p, FIREDANCER_DSQ, SCX_SLICE_DFL, 0);
		stat_inc(4);
	} else if (keep_in_kernel(p)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
	} else {
		scx_bpf_dsq_insert(p, OTHER_DSQ, SCX_SLICE_DFL, enq_flags);
		stat_inc(1);  /* count other tasks */
	}
}

void BPF_STRUCT_OPS(firedancer_dispatch, s32 cpu, struct task_struct *prev)
{

	u32 idle_pct = get_system_idle_percentage();
	bpf_printk("idle_pct: %d", idle_pct);
	int cpu_start = fd_cpu_start;
	int cpu_end = fd_cpu_end;
	if (idle_pct >= IDLE_PCT_THRESHOLD) {
		cpu_start = fd_cpu_start_idle;
		cpu_end = fd_cpu_end_idle;
	}

	if (cpu < cpu_end && cpu >= cpu_start) {
		if (scx_bpf_dsq_move_to_local(FIREDANCER_DSQ)) return;
	}
	if (scx_bpf_dsq_move_to_local(OTHER_DSQ)) return;

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