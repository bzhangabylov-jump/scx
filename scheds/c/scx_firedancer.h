// SPDX-License-Identifier: GPL-2.0

#ifndef __SCX_FD_H
#define __SCX_FD_H

#define MAX_ENQUEUED_TASKS 96

/*
 * An instance of a task that has been enqueued by the kernel for consumption
 * by a user space global scheduler thread.
 */
struct scx_fd_enqueued_task {
	__s32 pid;
	int64_t deadline_ts;
	u64 weight;
};

#endif  // __SCX_FD_H
