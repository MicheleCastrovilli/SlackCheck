// SPDX-License-Identifier: GPL-2.0
#include <linux/ftrace.h>
#include <linux/tracepoint.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/rv.h>
#include <linux/proc_fs.h>
#include <linux/kfifo.h>
#include <rv/instrumentation.h>
#include <rv/da_monitor.h>

#define MODULE_NAME "timed"

#define PATH_SIZE 1024
#define LATENCY_SIZE 21
#define ALPHA_NUM_SIZE 21
#define ALPHA_DEN_SIZE 21
#define PID_SIZE 21
#define CHECK_ALL_SIZE 2
#define PROC_FILENAME_PATH "rv_timed_proc_filename"
#define PROC_LATENCY_PATH  "rv_timed_latency_ns"
#define PROC_RATE_NUM_PATH "rv_timed_rate_num"
#define PROC_RATE_DEN_PATH "rv_timed_rate_den"
#define PROC_PID_PATH "rv_timed_proc_pid"
#define PROC_CHECK_ALL_PATH "rv_timed_check_all"

#define PROC_FIFO_PATH "rv_timed_fifo"
#define RV_FIFO_SIZE 128

#include <trace/events/sched.h>
#include <trace/events/rv.h>

/*
 * This is the self-generated part of the monitor. Generally, there is no need
 * to touch this section.
 */
#include "timed.h"

/*
 * Declare the deterministic automata monitor.
 *
 * The rv monitor reference is needed for the monitor declaration.
 */
static struct rv_monitor rv_timed;
DECLARE_DA_MON_GLOBAL(timed, unsigned char);

/*
 * This is the instrumentation part of the monitor.
 *
 * This is the section where manual work is required. Here the kernel events
 * are translated into model's event.
 *
 */

/*
 * Here is the structure of SlackCheck. The ts_sched_out/ts_sched_in
 * fields represent the timestamps at which the last sched_out/sched_in
 * event was received. alpha_num and alpha_den are expressing the rate alpha
 * of the lslbf (Equation 5), in integer values. This is due to the inefficiency
 * of floating point operations, so we store numerator and denominator separately.
 *
 * delta represents the delta parameter in Eq. 5. It is the latency of the lsblf,
 * expressed in ns.
 *
 * slack is the measure of the value expressed in Equation 7,8,9. It updates
 * at each sched_in/sched_out event relating to the PID of the monitored task.
 *
 * running is a simple boolean determining whether the monitored process is 
 * currently executing.
 *
 * pid is the PID of the monitored task.
 *
 * check_all is a boolean value determining whether to check if slack < 0, at
 * every other scheduling event the system generates, even of other tasks.
 * This allows SlackCheck to act much earlier than the first sched_in that is
 * "out of bounds".
 *
 * NOTE: In the current code, the slack value is allowed to be negative, to
 * generate the results of the paper. Therefore it will never react to a violation
 * of the condition.
 */

static struct rv_timed_struct {
	u64 ts_sched_out;
	u64 ts_sched_in;
	u64 alpha_num;
	u64 alpha_den;
	u64 delta;
	s64 slack;
	bool running;
	pid_t pid;
	bool check_all;
} rv_timed_struct;

struct rv_timed_file {
	char *content;
	int length;
};

/* These files represent the /proc filesystem interface. It is a rudimentary
 * way to pass information to the kernel module, in order to determine which
 * PID to monitor, with set alpha/delta.
 */

static struct rv_timed_file rv_timed_latency;
static struct rv_timed_file rv_timed_rate_numerator;
static struct rv_timed_file rv_timed_rate_denominator;
static struct rv_timed_file rv_timed_filename_proc;
static struct rv_timed_file rv_timed_pid_proc;
static struct rv_timed_file rv_timed_check_all;

struct kfifo_rec_ptr_1 rv_fifo;

struct proc_dir_entry *proc;

static void disable_timed(void);

#define rv_timed_get_struct() \
	&rv_timed_struct

static __always_inline void reset_monitor(void)
{
	struct rv_timed_struct *s = rv_timed_get_struct();

	s->pid = -1;
	s->running = false;
	s->ts_sched_out = 0;
	s->ts_sched_in = 0;
	s->check_all = false;
}

/**
 * handle_fork - records the start of the observed process
 *
 * Watches the sched_process_exec kernel events for a process with a certain
 * filename, and records its PID.
 */
static void handle_fork(void *data, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	struct rv_timed_struct *s = rv_timed_get_struct();

	if (strcmp(bprm->filename, rv_timed_filename_proc.content) == 0) {
		s->pid = p->pid;
		pr_info("SlackCheck: START PID %d\n", s->pid);
		da_handle_event_timed(fork_timed);
	}
}

/**
 * rv_timed_update_in - updates the automata information at a SCHED_IN event
 *
 * Updates both the timestamp for the last sched in event, and the relative
 * slack calculated from the previous value. This sched_in event only is related
 * to the PID being monitored. It updates slack according to Eq. 8.
 */
static void rv_timed_update_in(u64 current_time)
{
	struct rv_timed_struct *s = rv_timed_get_struct();
	u64 diff = 0;

	s->ts_sched_in = current_time;

	if (!s->running) {
		s->running = true;
		s->ts_sched_out = current_time;
		s->slack = s->delta; // out_0 = in_0 case
	} else {
		if (s->ts_sched_in > s->ts_sched_out)
			diff = s->ts_sched_in - s->ts_sched_out;
		else
			diff = 0;

		s->slack = s->slack - diff;
	}
}


/**
 * rv_timed_update_out - updates the automata information at a SCHED_OUT event
 *
 * Updates both the timestamp for the last sched out event, and the relative
 * slack calculated from the previous value. Updates slack according to Eq. 9.
 */
static void rv_timed_update_out(u64 current_time)
{
	struct rv_timed_struct *s = rv_timed_get_struct();
	u64 diff = 0;
	s64 slack_diff = 0;

	s->ts_sched_out = max(current_time, s->ts_sched_in);

	if (!s->running) {
		s->running = true;
		s->ts_sched_in = current_time;  // we consider out_0 this point, as we
										// could have missed in_0 as an event
		s->slack = s->delta;
	} else {
		diff = s->ts_sched_out > s->ts_sched_in ?
			s->ts_sched_out - s->ts_sched_in : 0;
		slack_diff = s->slack + (s64) div64_u64((s->alpha_den-s->alpha_num)*diff,
			s->alpha_num);	// numerator > 0, as num = 0 would indicate
							// a flat supply function, therefore the
							// intersecting point would be at infinity
		s->slack = min_t(s64, s->delta, slack_diff);
	}
}

static void check_slack(u64 current_time)
{
	struct rv_timed_struct *s = rv_timed_get_struct();

	if (!(s->running) && (current_time > s->ts_sched_out + s->slack)) {  // OUT OF TIME
		pr_info("SlackCheck: %d TIMEOUT BY: %llu ns\n",
				s->pid, s->slack);
		pr_info("SlackCheck: TIMEOUT - IN: %llu - OUT: %llu\n", s->ts_sched_in,
				s->ts_sched_out);
		da_handle_event_timed(terminate_timed);
		disable_timed();
		return;
	}
}

/**
 * handle_sched_switch - monitors the scheduling of the specified process
 *
 * Watches for the sched_switch events, recording the timestamps. Calculates
 * whether the process' supply function follows a certain linear lower bound.
 */
static void handle_sched_switch(void *data, bool preempt, struct task_struct *p,
			  struct task_struct *n, unsigned int prev_state)
{
	u64 current_time = ktime_get_boottime_ns();
	struct rv_timed_struct *s = rv_timed_get_struct();

	if (p->pid == s->pid) { // SCHED_OUT event
		rv_timed_update_out(current_time);
		pr_info("SlackCheck: OUT: %llu \t SLACK: %lld\n", current_time, s->slack);
		da_handle_event_timed(sched_out_timed);
	} else if (n->pid == s->pid) { // SCHED_IN event
		rv_timed_update_in(current_time);
		pr_info("SlackCheck: IN: %llu \t SLACK: %lld\n", current_time, s->slack);
		da_handle_event_timed(sched_in_timed);
		//check_slack(current_time); //Removing this comment will enable again
									 //the negative slack check. Currently the
									 //effect this causes is for the monitor to
									 //stop executing.
	} else if (s->check_all) {
		check_slack(current_time);
	}
}

/**
 * handle_terminate - Handles the termination of the specified process
 *
 * Watches for sched_process_exit events, filtering on the specified process
 * PID.
 */
static void handle_terminate(void *data, struct task_struct *p)
{
	struct rv_timed_struct *s = rv_timed_get_struct();

	if (p->pid == s->pid) {
		pr_info("SlackCheck: END %d\n", s->pid);
		da_handle_event_timed(terminate_timed);
		disable_timed();
	}
}

/* 
 * Function executed on Monitor enabling. It will attach a kernel probe
 * to the scheduling functions in order to monitor the execution of the system.
 */

static int enable_timed(void)
{
	int retval;

	retval = da_monitor_init_timed();
	if (retval)
		return retval;

	reset_monitor();

	rv_attach_trace_probe("timed", sched_process_exec, handle_fork);
	rv_attach_trace_probe("timed", sched_switch, handle_sched_switch);
	rv_attach_trace_probe("timed", sched_process_exit, handle_terminate);

	return 0;
}

/*
 * Function executed on a monitor disabling. Cleaning up the resources taken
 * up in the enable part, as well as resetting the internal SlackCheck values.
 */

static void disable_timed(void)
{
	rv_timed.enabled = 0;

	reset_monitor();

	rv_detach_trace_probe("timed", sched_process_exec, handle_fork);
	rv_detach_trace_probe("timed", sched_switch, handle_sched_switch);
	rv_detach_trace_probe("timed", sched_process_exit, handle_terminate);

	da_monitor_destroy_timed();
}

/*
 * This is the monitor register section.
 */
static struct rv_monitor rv_timed = {
	.name = "timed",
	.description = "module for SlackCheck",
	.enable = enable_timed,
	.disable = disable_timed,
	.reset = da_monitor_reset_all_timed,
	.enabled = 0,
};

/*
 * MONITOR FILENAME PROC FUNCTIONS
 *
 * These functions only govern the passage of data through the /proc filesystem.
 * This is for passing a filename of the process being monitored, rather than its
 * PID.
 */

static ssize_t timed_monitor_filename_read_data(struct file *filp,
	char __user *user_buf, size_t count, loff_t *ppos)
{
	int err;
	char *data = pde_data(file_inode(filp));

	if ((int) (*ppos) > rv_timed_filename_proc.length)
		return 0;

	if (count == 0)
		return 0;

	count = rv_timed_filename_proc.length + 1;
	err = copy_to_user(user_buf, data, count);
	*ppos = count;

	return count;
}

static ssize_t timed_monitor_filename_write_data(struct file *filp, const char __user *user_buf,
					 size_t count, loff_t *ppos)
{
	char *data = pde_data(file_inode(filp));

	if (count > PATH_SIZE)
		return -EFAULT;

	if (copy_from_user(data, user_buf, count))
		return -EFAULT;

	data[count-1] = '\0';
	rv_timed_filename_proc.length = count - 1;
	return count;
}

const struct proc_ops proc_fops = {
	.proc_read  = timed_monitor_filename_read_data,
	.proc_write = timed_monitor_filename_write_data,
};

/*
 * MONITOR LATENCY/DELTA PROC FUNCTIONS
 *
 * These functions only govern the passage of data through the /proc filesystem.
 */

static ssize_t timed_monitor_latency_read_data(struct file *filp, char __user *user_buf, size_t count,
					loff_t *ppos)
{
	int err;
	char *data = pde_data(file_inode(filp));

	if ((int) (*ppos) > rv_timed_latency.length)
		return 0;

	if (count == 0)
		return 0;

	count = rv_timed_latency.length + 1;
	err = copy_to_user(user_buf, data, count);
	*ppos = count;

	return count;
}

static ssize_t timed_monitor_latency_write_data(struct file *filp, const char __user *user_buf,
					 size_t count, loff_t *ppos)
{
	long long res;
	int err;
	char *data = pde_data(file_inode(filp));
	struct rv_timed_struct *s = rv_timed_get_struct();

	if (count > PATH_SIZE)
		return -EFAULT;

	err = kstrtoll_from_user(user_buf, count, 10, &res);
	if (err)
		return err;

	if (res < 100)
		return -EINVAL;

	s->delta = res;

	if (copy_from_user(data, user_buf, count))
		return -EFAULT;

	data[count-1] = '\0';
	rv_timed_latency.length = count - 1;
	return count;
}

const struct proc_ops proc_fops_latency = {
	.proc_read   = timed_monitor_latency_read_data,
	.proc_write  = timed_monitor_latency_write_data,
};

/*
 * MONITOR RATE/ALPHA NUMERATOR PROC FUNCTIONS
 */

static ssize_t timed_monitor_rate_num_read_data(struct file *filp, char __user *user_buf,
	size_t count, loff_t *ppos)
{
	int err;
	char *data = pde_data(file_inode(filp));

	if ((int) (*ppos) > rv_timed_rate_numerator.length)
		return 0;

	if (count == 0)
		return 0;

	count = rv_timed_rate_numerator.length + 1;
	err = copy_to_user(user_buf, data, count);
	*ppos = count;

	return count;
}

static ssize_t timed_monitor_rate_num_write_data(struct file *filp, const char __user *user_buf,
					 size_t count, loff_t *ppos)
{
	long long res;
	int err;
	char *data = pde_data(file_inode(filp));
	struct rv_timed_struct *s = rv_timed_get_struct();

	if (count > PATH_SIZE)
		return -EFAULT;

	err = kstrtoll_from_user(user_buf, count, 10, &res);
	if (err)
		return err;

	if (res < 1)
		return -EINVAL;

	if (res > s->alpha_den)
		return -EINVAL;

	s->alpha_num = res;

	if (copy_from_user(data, user_buf, count))
		return -EFAULT;

	data[count-1] = '\0';
	rv_timed_rate_numerator.length = count - 1;
	return count;
}

const struct proc_ops proc_fops_rate_num = {
	.proc_read   = timed_monitor_rate_num_read_data,
	.proc_write  = timed_monitor_rate_num_write_data,
};

/*
 * MONITOR RATE/ALPHA DENOMINATOR PROC FUNCTIONS
 */

static ssize_t timed_monitor_rate_den_read_data(struct file *filp, char __user *user_buf, size_t count,
					loff_t *ppos)
{
	int err;
	char *data = pde_data(file_inode(filp));

	if ((int) (*ppos) > rv_timed_rate_denominator.length)
		return 0;

	if (count == 0)
		return 0;

	count = rv_timed_rate_denominator.length + 1;
	err = copy_to_user(user_buf, data, count);
	*ppos = count;

	return count;
}

static ssize_t timed_monitor_rate_den_write_data(struct file *filp, const char __user *user_buf,
					 size_t count, loff_t *ppos)
{
	long long res;
	int err;
	char *data = pde_data(file_inode(filp));
	struct rv_timed_struct *s = rv_timed_get_struct();

	if (count > PATH_SIZE)
		return -EFAULT;

	err = kstrtoll_from_user(user_buf, count, 10, &res);
	if (err)
		return err;

	if (res < 1)
		return -EINVAL;

	if (res < s->alpha_num)
		return -EINVAL;

	s->alpha_den = res;

	if (copy_from_user(data, user_buf, count))
		return -EFAULT;

	data[count-1] = '\0';
	rv_timed_rate_denominator.length = count - 1;
	return count;
}

const struct proc_ops proc_fops_rate_den = {
	.proc_read   = timed_monitor_rate_den_read_data,
	.proc_write  = timed_monitor_rate_den_write_data,
};

/*
 * MONITOR PID WRITING PROC FUNCTIONS
 */

static ssize_t timed_monitor_pid_read_data(struct file *filp, char __user *user_buf, size_t count,
					loff_t *ppos)
{
	int err;
	char *data = pde_data(file_inode(filp));

	if ((int) (*ppos) > rv_timed_pid_proc.length)
		return 0;

	if (count == 0)
		return 0;

	count = rv_timed_pid_proc.length + 1;
	err = copy_to_user(user_buf, data, count);
	*ppos = count;

	return count;
}

static ssize_t timed_monitor_pid_write_data(struct file *filp, const char __user *user_buf,
					 size_t count, loff_t *ppos)
{
	long long res;
	int err;
	char *data = pde_data(file_inode(filp));
	struct rv_timed_struct *s = rv_timed_get_struct();

	if (count > PATH_SIZE)
		return -EFAULT;

	err = kstrtoll_from_user(user_buf, count, 10, &res);
	if (err)
		return err;

	if (res < 0)
		return -EINVAL;

	s->pid = res;

	if (copy_from_user(data, user_buf, count))
		return -EFAULT;

	data[count-1] = '\0';
	rv_timed_pid_proc.length = count - 1;
	return count;
}

const struct proc_ops proc_fops_pid = {
	.proc_read   = timed_monitor_pid_read_data,
	.proc_write  = timed_monitor_pid_write_data,
};

/*
 * MONITOR CHECK ALL WRITING PROC FUNCTIONS
 */

static ssize_t timed_monitor_ca_read_data(struct file *filp, char __user *user_buf, size_t count,
					loff_t *ppos)
{
	int err;
	char *data = pde_data(file_inode(filp));

	if ((int) (*ppos) > rv_timed_check_all.length)
		return 0;

	if (count == 0)
		return 0;

	count = rv_timed_check_all.length + 1;
	err = copy_to_user(user_buf, data, count);
	*ppos = count;

	return count;
}

static ssize_t timed_monitor_ca_write_data(struct file *filp, const char __user *user_buf,
					 size_t count, loff_t *ppos)
{
	long long res;
	int err;
	char *data = pde_data(file_inode(filp));
	struct rv_timed_struct *s = rv_timed_get_struct();

	if (count > PATH_SIZE)
		return -EFAULT;

	err = kstrtoll_from_user(user_buf, count, 10, &res);
	if (err)
		return err;

	if (res < 0 || res > 1)
		return -EINVAL;

	s->check_all = (bool) res;

	if (copy_from_user(data, user_buf, count))
		return -EFAULT;

	data[count-1] = '\0';
	rv_timed_check_all.length = count - 1;
	return count;
}

const struct proc_ops proc_fops_ca = {
	.proc_read   = timed_monitor_ca_read_data,
	.proc_write  = timed_monitor_ca_write_data,
};

/*
 * MONITOR FIFO WRITING PROC FUNCTIONS
 */

static ssize_t rv_fifo_write(struct file *file, const char __user *buf,
						size_t count, loff_t *ppos)
{
	return -EPERM;
}

static ssize_t rv_fifo_read(struct file *file, char __user *buf,
						size_t count, loff_t *ppos)
{
	int ret;
	unsigned int copied;

	ret = kfifo_to_user(&rv_fifo, buf, count, &copied);

	if (ret)
		return ret;

	return copied;
}

static const struct proc_ops fifo_proc_ops = {
	.proc_read	= rv_fifo_read,
	.proc_write	= rv_fifo_write,
	.proc_lseek	= noop_llseek,
};

/*
 * MONITOR CREATION FUNCTIONS
 *
 * Helper Function to create the /proc files in order to communicate with the
 * user. This subsystem could be upgraded to use tracefs in /sys/kernel/debug/trace.
 */

int create_new_proc_entry(void)
{
	char *DATA = "./test_counter";
	char *LATENCY = "1000000";
	char *ALPHA_NUM = "1";
	char *ALPHA_DEN = "2";
	char *PID = "-1";
	char *CHECK_ALL = "0";
	struct rv_timed_struct *s = rv_timed_get_struct();
	int ret;

	s->delta = 1000000;
	s->alpha_num = 1;
	s->alpha_den = 2;
	s->pid = -1;
	s->check_all = false;

	rv_timed_filename_proc.length = strlen(DATA);
	rv_timed_latency.length = strlen(LATENCY);
	rv_timed_rate_numerator.length = strlen(ALPHA_NUM);
	rv_timed_rate_denominator.length = strlen(ALPHA_DEN);
	rv_timed_pid_proc.length = strlen(PID);
	rv_timed_check_all.length = strlen(CHECK_ALL);

	rv_timed_filename_proc.content = kmalloc((size_t) PATH_SIZE, GFP_KERNEL);
	rv_timed_latency.content = kmalloc((size_t) LATENCY_SIZE, GFP_KERNEL);
	rv_timed_rate_numerator.content = kmalloc((size_t) ALPHA_NUM_SIZE, GFP_KERNEL);
	rv_timed_rate_denominator.content = kmalloc((size_t) ALPHA_DEN_SIZE, GFP_KERNEL);
	rv_timed_pid_proc.content = kmalloc((size_t) PID_SIZE, GFP_KERNEL);
	rv_timed_check_all.content = kmalloc((size_t) CHECK_ALL_SIZE, GFP_KERNEL);

	ret = kfifo_alloc(&rv_fifo, RV_FIFO_SIZE, GFP_KERNEL);
	if (ret) {
		pr_err("SlackCheck: error on allocating kfifo\n");
		return ret;
	}

	if (rv_timed_filename_proc.content == NULL ||
		rv_timed_latency.content == NULL ||
		rv_timed_rate_numerator.content == NULL ||
		rv_timed_rate_denominator.content == NULL ||
		rv_timed_pid_proc.content == NULL ||
		rv_timed_check_all.content == NULL
		)
		return -1;

	strscpy(rv_timed_filename_proc.content, DATA, rv_timed_filename_proc.length+1);
	strscpy(rv_timed_latency.content, LATENCY, rv_timed_latency.length+1);
	strscpy(rv_timed_rate_numerator.content, ALPHA_NUM, rv_timed_rate_numerator.length+1);
	strscpy(rv_timed_rate_denominator.content, ALPHA_DEN, rv_timed_rate_denominator.length+1);
	strscpy(rv_timed_pid_proc.content, PID, rv_timed_pid_proc.length+1);
	strscpy(rv_timed_check_all.content, CHECK_ALL, rv_timed_check_all.length+1);

	proc = proc_create_data(PROC_FILENAME_PATH, 0644, NULL, &proc_fops,
			rv_timed_filename_proc.content);
	if (!proc)
		return -1;
	proc = proc_create_data(PROC_LATENCY_PATH, 0644, NULL, &proc_fops_latency,
			rv_timed_latency.content);
	if (!proc)
		return -1;
	proc = proc_create_data(PROC_RATE_NUM_PATH, 0644, NULL, &proc_fops_rate_num,
			rv_timed_rate_numerator.content);
	if (!proc)
		return -1;
	proc = proc_create_data(PROC_RATE_DEN_PATH, 0644, NULL, &proc_fops_rate_den,
			rv_timed_rate_denominator.content);
	if (!proc)
		return -1;
	proc = proc_create_data(PROC_PID_PATH, 0644, NULL, &proc_fops_pid, rv_timed_pid_proc.content);
	if (!proc)
		return -1;
	proc = proc_create_data(PROC_CHECK_ALL_PATH, 0644, NULL, &proc_fops_ca,
			rv_timed_check_all.content);
	if (!proc)
		return -1;

	if (proc_create(PROC_FIFO_PATH, 0444, NULL, &fifo_proc_ops) == NULL) {
		kfifo_free(&rv_fifo);
		return -1;
	}

	return 0;
}


static int __init register_timed(void)
{
	if (create_new_proc_entry())
		return -1;

	rv_register_monitor(&rv_timed);
	return 0;
}

static void __exit unregister_timed(void)
{
	rv_unregister_monitor(&rv_timed);
	remove_proc_entry(PROC_FILENAME_PATH, NULL);
	remove_proc_entry(PROC_LATENCY_PATH, NULL);
	remove_proc_entry(PROC_RATE_NUM_PATH, NULL);
	remove_proc_entry(PROC_RATE_DEN_PATH, NULL);
	remove_proc_entry(PROC_PID_PATH, NULL);
	remove_proc_entry(PROC_CHECK_ALL_PATH, NULL);
	remove_proc_entry(PROC_FIFO_PATH, NULL);
	kfifo_free(&rv_fifo);
}

module_init(register_timed);
module_exit(unregister_timed);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michele Castrovilli");
MODULE_DESCRIPTION("timed");
