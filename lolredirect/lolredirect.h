#ifndef _LOLREDIRECT_H_
#define _LOLREDIRECT_H_

#include <cstdint>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>

#include "error.h"

constexpr int max_path_len = 2048;

struct syscall_mod {
	syscall_mod(int pid, int syscall_id, struct user_regs_struct *regs)
		:
		pid(pid),
		syscall_id(syscall_id),
		set_regs(false),
		regs(regs) {
	}

	int pid;
	int syscall_id;
	bool set_regs;
	struct user_regs_struct *regs;

	uint64_t *get_arg_ptr(int arg_id) {
		unsigned long long int *ret;
		switch (arg_id) {
		case 0:
			ret = &this->regs->rdi;
			break;
		case 1:
			ret = &this->regs->rsi;
			break;
		case 2:
			ret = &this->regs->rdx;
			break;
		case 3:
			ret = &this->regs->rcx;
			break;
		case 4:
			ret = &this->regs->r8;
			break;
		case 5:
			ret = &this->regs->r9;
			break;
		case 6:
			ret = &this->regs->r10;
			break;
		default:
			throw util::Error("unknown argument %d queried!", arg_id);
		}

		return (uint64_t *)ret;
	}

	uint64_t get_arg(int arg_id) {
		return *this->get_arg_ptr(arg_id);
	}

	void set_arg(int arg_id, uint64_t val) {
		*this->get_arg_ptr(arg_id) = val;
		this->set_regs = true;
	}

	void set_return(uint64_t val) {
		this->regs->rax = val;
		this->set_regs = true;
	}

	void print_registers() {
		printf("syscall %03d:\n"
		       "\targ0: 0x%016lx\n"
		       "\targ1: 0x%016lx\n"
		       "\targ2: 0x%016lx\n"
		       "\targ3: 0x%016lx\n"
		       "\targ4: 0x%016lx\n"
		       "\targ5: 0x%016lx\n"
		       "\targ6: 0x%016lx\n",
		       this->syscall_id, this->get_arg(0),
		       this->get_arg(1), this->get_arg(2),
		       this->get_arg(3), this->get_arg(4),
		       this->get_arg(4), this->get_arg(5));
	}
};

enum class redirect_reason {
	PATH,
	FD,
	NOTNEEDED,
};

struct decision {
	decision() : redirect(false) {};
	decision(bool def) : redirect(def) {};
	bool redirect;
	redirect_reason reason;
};

namespace util {
int tmemcpy(struct syscall_mod *trap, char *dest, const char *src, ssize_t len, bool to_other);
int tstrncpy(struct syscall_mod *trap, char *dest, const char *addr, ssize_t len);
int strpcmp(const char *search, const char *prefix);
}


void syscall_inject(struct syscall_mod *trap);


#endif //_LOLREDIRECT_H_
