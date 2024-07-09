/*
 * Automatically generated C representation of timed automaton
 * For further information about this format, see kernel documentation:
 *   Documentation/trace/rv/deterministic_automata.rst
 */

/*
 * This file represents the Automata as described in Figure 3 of the paper.
 * It was automatically generated from the dot2k program as described in
 * https://bristot.me/efficient-formal-verification-for-the-linux-kernel/
 */


enum states_timed {
	not_started_timed = 0,
	ready_timed,
	running_timed,
	terminated_timed,
	state_max_timed
};

#define INVALID_STATE state_max_timed

enum events_timed {
	fork_timed = 0,
	sched_in_timed,
	sched_out_timed,
	terminate_timed,
	event_max_timed
};

struct automaton_timed {
	char *state_names[state_max_timed];
	char *event_names[event_max_timed];
	unsigned char function[state_max_timed][event_max_timed];
	unsigned char initial_state;
	bool final_states[state_max_timed];
};

static const struct automaton_timed automaton_timed = {
	.state_names = {
		"not_started",
		"ready",
		"running",
		"terminated"
	},
	.event_names = {
		"fork",
		"sched_in",
		"sched_out",
		"terminate"
	},
	.function = {
		{         ready_timed,       INVALID_STATE,       INVALID_STATE,       INVALID_STATE },
		{       INVALID_STATE,       running_timed,       INVALID_STATE,    terminated_timed },
		{       INVALID_STATE,       INVALID_STATE,         ready_timed,    terminated_timed },
		{       INVALID_STATE,       INVALID_STATE,       INVALID_STATE,       INVALID_STATE },
	},
	.initial_state = not_started_timed,
	.final_states = { 0, 0, 0, 1 },
};
