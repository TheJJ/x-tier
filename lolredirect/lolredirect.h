#ifndef _LOLREDIRECT_H_
#define _LOLREDIRECT_H_

#include <cstdint>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>

#include "error.h"
#include "state_tracker.h"

constexpr int max_path_len = 2048;

struct process_state;

struct syscall_mod {
	syscall_mod(int pid, int syscall_id, struct user_regs_struct *regs, process_state *pstate);

	int pid;
	int syscall_id;
	bool set_regs;
	struct user_regs_struct *regs;
	struct process_state *pstate;

	uint64_t *get_arg_ptr(int arg_id);
	uint64_t get_arg(int arg_id);
	void set_arg(int arg_id, uint64_t val);
	void set_return(uint64_t val);
	void print_registers();
};

#endif //_LOLREDIRECT_H_
