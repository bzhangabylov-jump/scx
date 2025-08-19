/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE

#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_firedancer.bpf.skel.h"
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include "scx_firedancer.h"

const char help_fmt[] =
"A simple sched_ext scheduler for firedancer processes.\n"
"\n"
"WIP"
"\n"
"Usage: %s [-v] [-h]\n"
"\n"
"  -v            Print verbose debug output\n"
"  -h            Display this help and exit\n";

static bool verbose;
static volatile int exit_req;
static int enqueued_fd, dispatched_fd;
static int fd_idle_status_fd;
static int leader_fd, pid_to_cpu_fd, reserved_cpus_fd;

static struct scx_firedancer *skel;

/* Cache for tracking idle status to avoid unnecessary BPF map updates */
struct idle_cache_entry {
	int pid;
	u8 idle_status;
	int valid;
};
static struct idle_cache_entry idle_cache[50];

struct CircularQueue {
	struct scx_fd_enqueued_task arr[MAX_ENQUEUED_TASKS];
	int front;
	int back;
	int size;
};

void initialize_queue(struct CircularQueue* q) {
	q->front = 0;
	q->back = 0;
	q->size = 0;
}

void enqueue(struct CircularQueue* q, struct scx_fd_enqueued_task* item) {
	q->arr[q->back] = *item;
	q->back = (q->back + 1) % MAX_ENQUEUED_TASKS;
	if (q->back == q->front) {
		q->front = (q->front + 1) % MAX_ENQUEUED_TASKS;
	} else {
		q->size += 1;
	}
}

struct scx_fd_enqueued_task* dequeue(struct CircularQueue* q) {
	if (q->size > 0) {
		struct scx_fd_enqueued_task* ret_val = &(q->arr[q->front]);
		q->front = (q->front + 1) % MAX_ENQUEUED_TASKS;
		q->size -= 1;
		return ret_val;
	}
	errno = EINVAL;
	return NULL;
}

static void cleanup_idle_entry(s32 pid)
{
	if (fd_idle_status_fd > 0) {
		bpf_map_delete_elem(fd_idle_status_fd, &pid);
	}
}

static void dump_idle_status_map(void)
{
    if (fd_idle_status_fd <= 0) {
        printf("fd_idle_status map not available\n");
        return;
    }

    printf("\n=== DUMP: Complete fd_idle_status BPF Map ===\n");

    s32 key = -1, next_key;
    u8 value;
    int count = 0;

    /* Iterate through all entries in the map */
    while (bpf_map_get_next_key(fd_idle_status_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd_idle_status_fd, &next_key, &value) == 0) {
            printf("  PID %d -> %s (value=%d)\n",
                   next_key, value ? "IDLE" : "ACTIVE", value);
            count++;
        }
        key = next_key;
    }

    printf("Total entries in map: %d\n", count);
    printf("=== END DUMP ===\n\n");
}

static struct CircularQueue cq;

struct fd_scheduler_shm {
    int scheduler_pid;
    int test_counter;
	int is_leader;
    char message[256];
    struct {
        int pid;
		int registered;
        int idle;
		long deadline_ts;
		int cpu_id;
        char name[64];
    } tiles[50];
};

static u64 get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (u64)ts.tv_sec * 1000000000ULL + (u64)ts.tv_nsec;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static struct fd_scheduler_shm *g_shm = NULL;

static long get_deadline_ts_for_pid(int pid) {
    if (!g_shm) {
        return -1; /* unknown */
    }
    for (int i = 0; i < 50; i++) {
        if (g_shm->tiles[i].registered && g_shm->tiles[i].pid == pid) {
            return g_shm->tiles[i].deadline_ts;
        }
    }
    return -1; /* not found */
}

static void cleanup_shm(void) {
    if (g_shm) {
        munmap(g_shm, sizeof(struct fd_scheduler_shm));
    }
    shm_unlink("/fd_scheduler_shm");  // Remove the shared memory
}

static void sigint_handler(int simple)
{
	exit_req = 1;
}

static const char *get_name_for_pid(int pid) {
	if (!g_shm) {
		return "unknown";
	}
	for (int i = 0; i < 50; i++) {
		if (g_shm->tiles[i].registered && g_shm->tiles[i].pid == pid) {
			return g_shm->tiles[i].name;
		}
	}
	return "unknown";
}

static void print_queue_state() {
	printf("================ QUEUE STATE ==============\n");
	int cur = cq.front;
	long time_right_now = (long) get_time_ns();
	printf("TIME RIGHT NOW IS %ld\n", time_right_now);
	for (int i = 0; i < cq.size; i++) {
		int pid = cq.arr[cur].pid;
		long deadline_ts = get_deadline_ts_for_pid(pid);
		printf("pid: %d, deadline_ts: %ld, until deadline: %ld, name: %s \n", pid, deadline_ts, deadline_ts - time_right_now, get_name_for_pid(pid));
		cur = (cur + 1) % MAX_ENQUEUED_TASKS;
	}
}

static void read_stats(struct scx_firedancer *skel, __u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus();
	assert(nr_cpus > 0);
	__u64 cnts[6][nr_cpus];
	__u32 idx;

	memset(stats, 0, sizeof(stats[0]) * 6);

	for (idx = 0; idx < 5; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

static void *run_stats_printer(void *arg)
{
    while (!exit_req) {
        if (skel && !UEI_EXITED(skel, uei)) {
            __u64 stats[6];
            read_stats(skel, stats);

            printf("=== Firedancer Scheduler Stats 1.2 ===\n");
            printf("Firedancer tasks enqueued in US: %llu\n", stats[0]);
			printf("Firedancer enqueued in Kernel: %llu\n", stats[4]);
			printf("Firedancer enqueued in Kernel (needed for replay): %llu\n", stats[5]);
			printf("Firedancer tasks dispatched in select_cpu: %llu\n", stats[2]);
            printf("Other tasks enqueued in kernel: %llu\n", stats[1]);
			printf("Other tasks dispatched in select_cpu: %llu\n", stats[3]);
			printf("queue size: %d\n", cq.size);
			printf("is leader: %d\n", g_shm->is_leader);

			long time_right_now = get_time_ns();
            if (g_shm) {
                printf("\n=== Registered Tiles ===\n");
                for (int i = 0; i < 50; i++) {
                    if (g_shm->tiles[i].registered) {
                        printf("[%2d] %-16s pid=%-6d %s deadline in %ld us cpu=%d\n",
                               i, g_shm->tiles[i].name,
                               g_shm->tiles[i].pid,
                               g_shm->tiles[i].idle ? "IDLE" : "ACTIVE",
						   g_shm->tiles[i].idle ? (g_shm->tiles[i].deadline_ts - time_right_now) / 1000 : 0,
						   g_shm->tiles[i].cpu_id);
                    }
                }
            }
			dump_idle_status_map();
			print_queue_state();
            fflush(stdout);
        }
        sleep(1);
    }
    return NULL;
}

static int spawn_stats_thread(void)
{
	pthread_t stats_thread;
    return pthread_create(&stats_thread, NULL, run_stats_printer, NULL);
}

int user_space_schedule(struct scx_fd_enqueued_task *task)
{
	// task->deadline_ts = get_deadline_ts_for_pid(task->pid);
	task->deadline_ts = get_time_ns() + 10000000000; // 10 second
	enqueue(&cq, task);
	return 0;
}

static void drain_enqueued_map(void)
{
	while (1) {
		struct scx_fd_enqueued_task task;
		int err;
		if (bpf_map_lookup_and_delete_elem(enqueued_fd, NULL, &task)) {
			return;
		};
		err = user_space_schedule(&task);
		if (err) {
			fprintf(stderr, "Failed to schedule task in user space %d: %s\n",
				task.pid, strerror(err));
			exit_req = 1;
			return;
		}
	}
}

static void dispatch_batch(void)
{
	/* If leader, immediately dispatch all held tasks */
	if (g_shm && g_shm->is_leader) {
		int held = cq.size;
		for (int i = 0; i < held; i++) {
			struct scx_fd_enqueued_task* task = dequeue(&cq);
			if (!task) continue;
			int err = bpf_map_update_elem(dispatched_fd, NULL, &task->pid, 0);
			if (err) {
				printf("failed to update dispatch map %d\n", task->pid);
			}
		}
		return;
	}

	/* Not leader: hold tasks; optional time-based dispatch if desired */
	ulong time = get_time_ns();
	for (int i = 0; i < cq.size; i++) {
		struct scx_fd_enqueued_task* task = dequeue(&cq);
		if (!task) continue;
		if ((long) time >= task->deadline_ts) {
			int err = bpf_map_update_elem(dispatched_fd, NULL, &task->pid, 0);
			if (err) {
				printf("failed to update dispatch map %d", task->pid);
			}
		} else {
			/* Not ready yet; push back for a future round */
			enqueue(&cq, task);
		}
	}
	return;
}

static int tile_is_exempt(const char *name) {
    if (!name) return 0;
    // Prefix matches (adjust to your exact naming)
    // if (!strncmp(name, "net", 3))    return 1;
    // if (!strncmp(name, "shred", 5))  return 1;
	// if (!strncmp(name, "sign", 4))  return 1;
    // if (!strncmp(name, "poh", 3))    return 1;
    // if (!strncmp(name, "gui", 3))    return 1;
    // if (!strncmp(name, "metric", 6)) return 1;
    // if (!strncmp(name, "netlnk", 6)) return 1;
    // if (!strncmp(name, "cswtch", 6)) return 1;
    // if (!strncmp(name, "store", 5)) return 1;
	// if (!strncmp(name, "plugin", 6)) return 1;
	// // if (!strncmp(name, "pack", 6)) return 1;
	// // if (!strncmp(name, "bank", 4))  return 1;
	// if (!strncmp(name, "verify", 6))  return 1;
	// if (!strncmp(name, "quic", 6))  return 1;
	// if (!strncmp(name, "resolv", 6))  return 1;
	// if (!strncmp(name, "dedup", 5))  return 1;
    return 0;
}

static int tile_not_needed(const char *name) {
	if (!name) return 0;
	if (!strncmp(name, "verify", 3))    return 1;
	if (!strncmp(name, "pack", 6)) return 1;
	if (!strncmp(name, "bank", 4))  return 1;

	// if (!strncmp(name, "quic", 4))  return 1;
	return 0;
}

static void update_leader_map_from_shm(void)
{
	if (leader_fd <= 0 || !g_shm) return;
	u32 key = 0;
	u32 val = g_shm->is_leader ? 1 : 0;
	bpf_map_update_elem(leader_fd, &key, &val, BPF_ANY);
}

static void update_affinity_maps_from_shm(void)
{
	if (!g_shm) return;
	/* Update leader state first */
	update_leader_map_from_shm();

	/* Update pid->cpu and reserved cpus */
	if (pid_to_cpu_fd <= 0 || reserved_cpus_fd <= 0) return;

	int cpus = libbpf_num_possible_cpus();
	if (cpus > 512) cpus = 512;

	/* Clear reserved when not leader */
	if (!g_shm->is_leader) {
		for (u32 c = 0; c < (u32)cpus; c++) {
			u8 zero = 0;
			bpf_map_update_elem(reserved_cpus_fd, &c, &zero, BPF_ANY);
		}
	}

	/* Track which CPUs are reserved when leader, TODO: can just be done at the start */
	u8 reserved[512] = {0};
	for (int i = 0; i < 50; i++) {
		if (g_shm->tiles[i].registered) {
			s32 pid = g_shm->tiles[i].pid;
			s32 cpu = g_shm->tiles[i].cpu_id;
			if (cpu >= 0 && cpu < cpus) reserved[cpu] = 1;
			if (pid) bpf_map_update_elem(pid_to_cpu_fd, &pid, &cpu, BPF_ANY);
		}
	}
	if (g_shm->is_leader) {
		for (u32 c = 0; c < (u32)cpus; c++) {
			u8 v = reserved[c];
			bpf_map_update_elem(reserved_cpus_fd, &c, &v, BPF_ANY);
		}
	}
}

static void update_idle_status_from_shm(void)
{
	if (!g_shm || fd_idle_status_fd <= 0)
		return;

	/* Update BPF map only when idle status changes */
	for (int i = 0; i < 50; i++) {
		if (g_shm->tiles[i].registered) {
			s32 pid = g_shm->tiles[i].pid;
			// u8 idle_status = g_shm->tiles[i].idle ? 1 : 0;
			// u8 idle_status = (!g_shm->is_leader && !tile_is_exempt(g_shm->tiles[i].name)) ? 1
            //                    : (g_shm->tiles[i].idle ? 1 : 0);
			// u8 idle_status = (!g_shm->is_leader && !tile_is_exempt(g_shm->tiles[i].name));
			u8 idle_status = (!g_shm->is_leader && tile_not_needed(g_shm->tiles[i].name));

			/* Check if we need to update - either new entry or status changed */
			if (!idle_cache[i].valid ||
			    idle_cache[i].pid != pid ||
			    idle_cache[i].idle_status != idle_status) {

				if (bpf_map_update_elem(fd_idle_status_fd, &pid, &idle_status, BPF_ANY) == 0) {
					idle_cache[i].pid = pid;
					idle_cache[i].idle_status = idle_status;
					idle_cache[i].valid = 1;
				} else {
					printf("Failed to update idle status for PID %d: %s\n", pid, strerror(errno));
					exit(1);
				}
			}
		} else if (idle_cache[i].valid) {
			/* Tile was unregistered, clean up */
			printf("Tile was unregistered, cleaning up, pid: %d\n", idle_cache[i].pid);
			exit(1);
			cleanup_idle_entry(idle_cache[i].pid);
			idle_cache[i].valid = 0;
		}
	}

	/* Maintain leader/pid->cpu/reserved cpu maps */
	update_affinity_maps_from_shm();
}

static int relaxed_affinity[50];

static void relax_affinity_for_new_tiles(void) {
	if (!g_shm) return;
    int cpus = libbpf_num_possible_cpus();
    if (cpus <= 0) return;

    cpu_set_t all;
    CPU_ZERO(&all);
    for (int c = 0; c < cpus && c < (int)CPU_SETSIZE; c++) CPU_SET(c, &all);

    for (int i = 0; i < 50; i++) {
        if (!g_shm->tiles[i].registered) continue;
        if (relaxed_affinity[i]) continue;

        s32 pid = g_shm->tiles[i].pid;
        s32 cpu = g_shm->tiles[i].cpu_id;

        if (pid_to_cpu_fd > 0)
            bpf_map_update_elem(pid_to_cpu_fd, &pid, &cpu, BPF_ANY);

        /* Allow anywhere while not leader */
        sched_setaffinity(pid, sizeof(all), &all);

        relaxed_affinity[i] = 1;
    }
}

static void sched_main_loop(void)
{
	u64 last_loop = 0;
	int idle_update_counter = 0;

    while (!exit_req && !UEI_EXITED(skel, uei)) {
        u64 now = get_time_ns();
        if (last_loop && (now - last_loop) > 1000000) { // 1 millisecond
            printf("WARNING: Loop blocked for %lu milliseconds!\n", (now - last_loop) / 1000000);
        }
        last_loop = now;

        drain_enqueued_map();
        dispatch_batch();

		relax_affinity_for_new_tiles();
        /* Update idle status frequently - every 1000 iterations */
        // if (++idle_update_counter >= 1000) {
            // idle_update_counter = 0;
		update_idle_status_from_shm();
        // }
    }
}

static int setup_shm(void) {
	mode_t old_umask = umask(0);
	int shm_fd = shm_open("/fd_scheduler_shm", O_CREAT | O_EXCL | O_RDWR, 0666);
	umask(old_umask);
    if (shm_fd >= 0) {
        if (ftruncate(shm_fd, sizeof(struct fd_scheduler_shm)) < 0) {
            printf("Failed to set shm size: %s\n", strerror(errno));
            close(shm_fd);
            return 1;
        }

        g_shm = mmap(NULL, sizeof(struct fd_scheduler_shm),
                     PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
        if (g_shm != MAP_FAILED) {
            printf("Created shared memory for scheduler\n");

            // Initialize the shared memory
            memset(g_shm, 0, sizeof(*g_shm));
            g_shm->scheduler_pid = getpid();
			g_shm->is_leader = 0;
            strcpy(g_shm->message, "Scheduler started");

            printf("Scheduler PID: %d\n", g_shm->scheduler_pid);
        } else {
			printf("Failed to map shared memory: %s\n", strerror(errno));
            close(shm_fd);
            return -1;
		}
        close(shm_fd); // Can close fd after mmap
    } else {
		if (errno == EEXIST) {
			printf("Shared memory already exists. Another scheduler running?\n");
		}
        printf("Failed to create shared memory: %s\n", strerror(errno));
        return -1;
    }
	return 1;
}

int main(int argc, char **argv)
{
	struct sched_param param = {
		.sched_priority = sched_get_priority_max(SCHED_FIFO) - 1
	};
	if (sched_setscheduler(0, SCHED_FIFO, &param) < 0) {
		perror("Failed to set real-time priority");
	}
	initialize_queue(&cq);

	int shm_ret = setup_shm();
	if (shm_ret < 0) {
		cleanup_shm();
		return shm_ret;
	}

	struct bpf_link *link;
	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(firedancer_ops, scx_firedancer);

	while ((opt = getopt(argc, argv, "vh")) != -1) {
		switch (opt) {
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_OPS_LOAD(skel, firedancer_ops, scx_firedancer, uei);

	enqueued_fd = bpf_map__fd(skel->maps.enqueued);
	dispatched_fd = bpf_map__fd(skel->maps.dispatched);
	fd_idle_status_fd = bpf_map__fd(skel->maps.fd_idle_status);
	leader_fd = bpf_map__fd(skel->maps.leader_state);
	pid_to_cpu_fd = bpf_map__fd(skel->maps.pid_to_cpu);
	reserved_cpus_fd = bpf_map__fd(skel->maps.reserved_cpus);
	assert(enqueued_fd > 0);
	assert(dispatched_fd > 0);
	assert(fd_idle_status_fd > 0);
	assert(leader_fd > 0);
	assert(pid_to_cpu_fd > 0);
	assert(reserved_cpus_fd > 0);

	SCX_BUG_ON(spawn_stats_thread(), "Failed to spawn stats thread");

	link = SCX_OPS_ATTACH(skel, firedancer_ops, scx_firedancer);

	printf("Firedancer scheduler running.\n");

	sched_main_loop();

	exit_req = 1;
	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_firedancer__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;

	cleanup_shm();
	return 0;
}