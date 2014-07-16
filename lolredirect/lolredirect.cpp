#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/reg.h>

//TODO: argparse
#define TARGET "./target-test"

#define HARMLESS_SYSCALL SYS_getuid

struct syscall_interception {
	syscall_interception(int pid, int syscall_id, struct user_regs_struct *regs)
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
};

struct decision {
	bool redirect;
	bool inject;
};


struct decision redirect_decision(struct syscall_interception *trap) {
	struct decision ret{false, false};

	switch (trap->syscall_id) {
	case SYS_open:
		ret.redirect = false;
		break;
	case SYS_getuid:
		ret.inject = true;
		break;
	}

	return ret;
}

void syscall_inject(struct syscall_interception *trap) {
	if (trap->syscall_id == SYS_getuid) {
		printf("changing getuid return value\n");
		trap->regs->rax = 42;
		trap->set_regs = true;
	}
}

int main() {
	int  status   = 0;

	int pid = fork();

	if (!pid) {
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		int target_status = execlp(TARGET, TARGET, 0);
		if (target_status == -1) {
			printf("target exec fail'd!");
		}
	}
	else {
		wait(&status);

		struct decision what_do;
		struct user_regs_struct regs;
		int syscall_id;

		while (true) {
			//wait for syscall trap
			ptrace(PTRACE_SYSCALL, pid, 0, 0);
			wait(&status);

			if (WIFEXITED(status)) {
				break;
			}

			ptrace(PTRACE_GETREGS, pid, 0, &regs);
			syscall_id = regs.orig_rax;
			printf("syscall trapped: %d\n", syscall_id);

			struct syscall_interception trap{pid, syscall_id, &regs};

			what_do = redirect_decision(&trap);

			if (what_do.redirect) {
				//replace syscall id with getuid:
				regs.orig_rax = HARMLESS_SYSCALL;
				ptrace(PTRACE_SETREGS, pid, 0, &regs);
			}

			//let the syscall run, wait for syscall exit:
			ptrace(PTRACE_SYSCALL, pid, 0, 0);
			wait(&status);

			if (what_do.inject) {
				syscall_inject(&trap);
				if (trap.set_regs) {
					ptrace(PTRACE_SETREGS, pid, 0, &regs);
				}
			}
		}
	}

	return 0;
}
