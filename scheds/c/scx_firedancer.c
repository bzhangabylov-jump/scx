/* SPDX-License-Identifier: GPL-2.0 */

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

static struct scx_firedancer *skel;

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

static struct CircularQueue cq;

struct fd_scheduler_shm {
    int scheduler_pid;
    int test_counter;
    char message[256];
    struct {
        int pid;
		int registered;
        int idle;
		long deadline_ts;
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

static void read_stats(struct scx_firedancer *skel, __u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus();
	assert(nr_cpus > 0);
	__u64 cnts[5][nr_cpus];
	__u32 idx;

	memset(stats, 0, sizeof(stats[0]) * 5);

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
            __u64 stats[5];
            read_stats(skel, stats);

            printf("=== Firedancer Scheduler Stats 1.2 ===\n");
            printf("Firedancer tasks: %llu\n", stats[0]);
            printf("Other tasks: %llu\n", stats[1]);
			printf("Select cpu firedancer: %llu\n", stats[2]);
			printf("Select cpu other: %llu\n", stats[3]);
			printf("Scheduler Descheduled Count: %llu\n", stats[4]);
			printf("queue size: %d\n", cq.size);

			long time_right_now = get_time_ns();
            if (g_shm) {
                printf("\n=== Registered Tiles ===\n");
                for (int i = 0; i < 50; i++) {
                    if (g_shm->tiles[i].registered) {
                        printf("[%2d] %-16s pid=%-6d %s deadline in %ld us\n",
                               i, g_shm->tiles[i].name,
                               g_shm->tiles[i].pid,
                               g_shm->tiles[i].idle ? "IDLE" : "ACTIVE",
							   g_shm->tiles[i].idle ? (g_shm->tiles[i].deadline_ts - time_right_now) / 1000 : 0);
                    }
                }
            }
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
	for (int i = 0; i < cq.size; i++) {
		struct scx_fd_enqueued_task* task = dequeue(&cq);
		if (task) {
			int err;
			err = bpf_map_update_elem(dispatched_fd, NULL, &task->pid, 0);
			if (err) {
				printf("failed to update dispatch map %d", task->pid);
			}
		}
	}
	return;
}

static void sched_main_loop(void)
{
	u64 last_loop = 0;
    while (!exit_req && !UEI_EXITED(skel, uei)) {
        u64 now = get_time_ns();
        if (last_loop && (now - last_loop) > 1000000) { // 1 millisecond
            printf("WARNING: Loop blocked for %lu milliseconds!\n", (now - last_loop) / 1000000);
        }
        last_loop = now;

        drain_enqueued_map();
        dispatch_batch();
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
	assert(enqueued_fd > 0);
	assert(dispatched_fd > 0);

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