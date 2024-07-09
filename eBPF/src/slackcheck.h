/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __SLACKCHECK_H
#define __SLACKCHECK_H

#define TASK_COMM_LEN	 16
#define MAX_FILENAME_LEN 127

enum sched_event {
	SCHED_IN,
	SCHED_OUT
};

struct event {
	int pid;
	enum sched_event switch_event;
	unsigned long long ts;
};

struct slack {
	__u64 ts_in;
	__u64 ts_out;
	__s64 slack;
};

#endif /* __SLACKCHECK_H */
