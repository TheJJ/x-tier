#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

//TODO: argparse
#define TARGET "./target-test"

#define HARMLESS_SYSCALL SYS_getuid


/*
 * rax  system call number
 * rdi  arg0
 * rcx  return address for syscall/sysret, C arg3
 * rsi  arg1
 * rdx  arg2
 * r10  arg3 (--> moved to rcx for C)
 * r8   arg4
 * r9   arg5
 * r11  eflags for syscall/sysret, temporary for C
 * r12-r15,rbp,rbx saved by C code, not touched.
 */

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


/*
 * copy len bytes from process pid at address addr to destination dest
 */
int umoven(struct syscall_interception *trap, long addr, int len, char *dest) {
	int n, nread;

	struct iovec local[1], remote[1];

	local[0].iov_base  = dest;
	remote[0].iov_base = (void*)addr;
	local[0].iov_len   = remote[0].iov_len = len;

	n = process_vm_readv(trap->pid, local, 1, remote, 1, 0);

	if (n == len) {
		return 0;
	}

	if (n >= 0) {
		printf("umoven: short read (%d < %d) @0x%lx\n", n, len, addr);
		return -1;
	}

	switch (errno) {
	case ENOSYS:
		printf("process_vm_readv syscall unsupported!\n");
		return -1;
	case ESRCH:
		/* the process is gone */
		return -1;
	case EFAULT:
	case EIO:
	case EPERM:
		/* address space is inaccessible */
		return -1;
	default:
		printf("unhandled error in umoven!\n");
		return -1;
	}
}


int umovestr(struct syscall_interception *trap, long addr, int len, char *dest) {
	constexpr int max_chunk_len = 256;
	int n, nread;

	nread = 0;
	struct iovec local[1], remote[1];

	local[0].iov_base = dest;
	remote[0].iov_base = (void*)addr;

	while (len > 0) {
		int end_in_page;
		int chunk_len;

		chunk_len = len;
		if (chunk_len > max_chunk_len) {
			chunk_len = max_chunk_len;
		}

		// honor page boundaries, EFAULT otherwise while the \0 is in previous page
		end_in_page = ((addr + chunk_len) & (4096 - 1));
		n = chunk_len - end_in_page;

		if (chunk_len > end_in_page) {
			chunk_len -= end_in_page;
		}

		local[0].iov_len = remote[0].iov_len = chunk_len;

		n = process_vm_readv(trap->pid, local, 1, remote, 1, 0);

		if (n > 0) {
			if (memchr(local[0].iov_base, '\0', n)) {
				return 1;
			}

			local[0].iov_base   = (void *)(((char *)local[0].iov_base)  + n);
			remote[0].iov_base  = (void *)(((char *)remote[0].iov_base) + n);
			len                -= n;
			nread              += n;
			continue;
		}

		switch (errno) {
		case ENOSYS:
			printf("process_vm_readv syscall unsupported!\n");
			return -1;
		case ESRCH:
			/* the process is gone */
			return -1;
		case EFAULT:
		case EIO:
		case EPERM:
			/* address space is inaccessible */
			if (nread) {
				printf("umovestr: short read (%d < %d) @0x%lx", nread, nread + len, addr);
			}
			return -1;
		default:
			printf("unhandled error in umovestr!\n");
			return -1;
		}
	}
	return 0;
}



struct decision redirect_decision(struct syscall_interception *trap) {
	struct decision ret{false, false};

	printf("syscall %d: arg0: 0x%llx arg1: 0x%llx arg2: 0x%llx arg3: 0x%llx arg4: 0x%llx arg5: 0x%llx arg6: 0x%llx\n",
	       trap->syscall_id, trap->regs->rdi,
	       trap->regs->rsi, trap->regs->rdx,
	       trap->regs->rcx, trap->regs->r8,
	       trap->regs->r9, trap->regs->r10);

	switch (trap->syscall_id) {
	case SYS_open: {
		//process_vm_readv();
		char path[1024];
		int n = umovestr(trap, trap->regs->rdi, 1024, path);

		if (n > 0) {
			printf("open: %s\n", path);
		}

		ret.redirect = false;
		break;
	}
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
