// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "slackcheck.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, pid_t);
	__type(value, struct slack);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} slack_values SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile pid_t monitored = 0;

void handle_sched(enum sched_event evt, pid_t pid, __u64 ts) {
	struct event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return;
	e->pid = pid;
	e->ts = ts;
	e->switch_event = evt;

	bpf_ringbuf_submit(e, 0);
}

SEC("raw_tp/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	u64 ts = bpf_ktime_get_ns();
    pid_t p = BPF_CORE_READ(prev, pid);
	if (bpf_map_lookup_elem(&slack_values, &p))
		handle_sched(SCHED_OUT, p, ts);

    p = BPF_CORE_READ(next, pid);
	if (bpf_map_lookup_elem(&slack_values, &p))
		handle_sched(SCHED_IN, p, ts);

	return 0;
}

