// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "slackcheck.h"
#include "slackcheck.skel.h"
#include <sys/param.h>

static struct env {
	bool verbose;
	long long alpha_num;
	long long alpha_den;
	long long latency_ns;
	pid_t monitored;
} env;

bool pid_given = false;
int sv = 0;

const char *sched_states[] = {"SCHED_IN", "SCHED_OUT"};
const char *argp_program_version = "slackcheck 0.0";
const char *argp_program_bug_address = "<michele.castrovilli@unito.it>";
const char argp_program_doc[] = "SlackCheck eBPF prototype.\n"
				"\n"
				"It traces a given process PID sched_switch events, showing the associated \n"
				"slack. Will also write to a .csv file in the same folder with the PID name.\n"
				"It takes two parameters, latency and rate (in numerator/denominator form), and \n"
				"calculates the remaining time before an intersection with a linear lower bound of\n"
				"the given parameters.\n"
				"\n"
				"USAGE: ./slackcheck -p <PID> -l <latency-ns> -a <alpha-numerator> -d <alpha-denominator> [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'l', "LATENCY-NS", 0, "Latency parameter of the given linear lower bound" },
	{ "alpha-num", 'a', "ALPHA-NUM", 0, "Numerator of the rate parameter of the given linear lower bound" },
	{ "alpha-den", 'd', "ALPHA-DEN", 0, "Denominator of the rate parameter of the given linear lower bound" },
	{ "pid", 'p', "PID", 0, "PID of the task to monitor"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'l':
		errno = 0;
		env.latency_ns = strtol(arg, NULL, 10);
		if (errno || env.latency_ns <= 0) {
			fprintf(stderr, "Invalid latency: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'a':
		errno = 0;
		env.alpha_num = strtol(arg, NULL, 10);
		if (errno || env.alpha_num <= 0) {
			fprintf(stderr, "Invalid alpha numerator: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'd':
		errno = 0;
		env.alpha_den = strtol(arg, NULL, 10);
		if (errno || env.alpha_den <= 0) {
			fprintf(stderr, "Invalid alpha denominator: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'p':
		errno = 0;
		env.monitored = strtol(arg, NULL, 10);
		if (errno || env.monitored <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		pid_given = true;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	case ARGP_KEY_END:
		if (!pid_given)
			argp_error(state, "PID to monitor not given.");
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct slack s;
	long long diff;

	bpf_map_lookup_elem(sv, &env.monitored, &s);
	
	if (s.ts_out == 0) {
		s.ts_out = e->ts;
		s.ts_in = e->ts;
		s.slack = env.latency_ns;
		goto update;
	}

	if (e->switch_event == SCHED_IN) {
		s.ts_in = e->ts;
		diff = s.ts_in - s.ts_out;
//		printf("DIFF IN %llu OUT %llu  - %lli\n ", s.ts_in, s.ts_out, diff);
		s.slack = s.slack - diff;
	} else {
		s.ts_out = e->ts;
		diff = s.ts_out - s.ts_in;
//		printf("DIFF %lli NUM %lli DEN %lli\n", diff, env.alpha_num, env.alpha_den);
		diff = s.slack + ((env.alpha_den-env.alpha_num)*diff)/env.alpha_num;
//		printf("SLACK %lli\n ", diff);
		s.slack = env.latency_ns < diff ? env.latency_ns : diff;  
	}
	
update:
	printf("%llu %-10s %d %lli\n", e->ts, sched_states[e->switch_event], e->pid, s.slack);
	bpf_map_update_elem(sv, &env.monitored, &s, 0);

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct slackcheck_bpf *skel;
	struct slack s = {};
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = slackcheck_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = slackcheck_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = slackcheck_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	sv = bpf_obj_get("/sys/fs/bpf/slack_values");
	if (!sv) {
		err = -1;
		fprintf(stderr, "Failed to get hash map\n");
		goto cleanup;
	}

	bpf_map_update_elem(sv, &env.monitored, &s, 0);
	
	/* Process events */
	printf("%-8s %-10s %-7s %-10s\n", "TIME", "EVENT", "PID", "SLACK");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	slackcheck_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
