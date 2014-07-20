#include "lolredirect.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "syscall_handler.h"
#include "syscall_utils.h"

#include "x-inject.h"

//TODO: argparse
#define TARGET "./target-test"

#define HARMLESS_SYSCALL SYS_getuid

constexpr bool print_syscalls = false;

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


struct decision redirect_decision(struct syscall_mod *trap) {
	if (print_syscalls) {
		trap->print_registers();
	}

	PRINT_DEBUG("encountered syscall %03d => %s\n", trap->syscall_id, syscall_name(trap->syscall_id));

	char path[max_path_len];

	int fd = -1;
	int n  = 0;

	//disable redirection by default
	struct decision ret{false};
	bool do_path_fd_test = true;

	//gather information about the trapped syscall
	switch (trap->syscall_id) {
	case SYS_open:
	case SYS_stat:
	case SYS_lstat:
		n = util::tstrncpy(trap, path, (char *)trap->get_arg(0), max_path_len);
		break;
	case SYS_openat:
		n = util::tstrncpy(trap, path, (char *)trap->get_arg(1), max_path_len);
		break;
	case SYS_write:
	case SYS_read:
	case SYS_close:
	case SYS_fstat:
	case SYS_lseek:
	case SYS_fcntl:
	case SYS_fadvise64:
	case SYS_getdents:
		fd = trap->get_arg(0);
		break;
	default:
		do_path_fd_test = false;
	}

	if (ret.redirect == false && do_path_fd_test) {
		if (n > 0) {
			const char *prefixes[] = {
				"/usr/lib/",
				"/lib/",
				"/lib64/",
				"/proc/self/",
				"/dev/tty",
				"/etc/ld.so.cache",
			};

			bool host_path = false;

			for (auto &prefix : prefixes) {
				if (0 == util::strpcmp(path, prefix)) {
					host_path = true;
					break;
				}
			}

			if (not host_path) {
				if (0 != strstr(path, "locale")
				    or 0 != strstr(path, "NOFWD")) {
					host_path = true;
				}
			}

			if (host_path) {
				PRINT_DEBUG("\tpath on host: %s\n", path);
				ret.redirect = false;
			} else {
				PRINT_DEBUG("\tpath on guest: %s\n", path);
				ret.redirect = true;
			}
			ret.reason = redirect_reason::PATH;
		}

		if (fd >= 0) {
			if (fd < FILE_DESCRIPTOR_OFFSET) {
				PRINT_DEBUG("\tfd %d on host.\n", fd);
				ret.redirect = false;
			}
			else {
				PRINT_DEBUG("\tfd %d on guest.\n", fd);
				ret.redirect = true;
			}
			ret.reason = redirect_reason::FD;
		}
	} else {
		ret.redirect = false;
		ret.reason = redirect_reason::NOTNEEDED;
	}

	if (ret.redirect) {
		PRINT_DEBUG("\t`-> redirect syscall %d\n", trap->syscall_id);
	}
	else {
		PRINT_DEBUG("\t`-> syscall %d regular on host!\n", trap->syscall_id);
	}

	return ret;
}

int run(int argc, char **argv) {
	int status = 0;

	int pid = fork();

	if (!pid) {
		PRINT_DEBUG("exec %s\n", argv[0]);

		ptrace(PTRACE_TRACEME, 0, 0, 0);
		int target_status = execvp(argv[0], argv);
		if (target_status == -1) {
			PRINT_DEBUG("target exec fail'd!");
		}
	}
	else {
		wait(&status);

		struct decision what_do;
		struct user_regs_struct regs;
		int syscall_id;

		//TODO: port argument
		init_connection(8998);

		while (true) {
			//wait for syscall trap
			ptrace(PTRACE_SYSCALL, pid, 0, 0);
			wait(&status);

			if (WIFEXITED(status)) {
				PRINT_INFO("Child exit with status %d\n", WEXITSTATUS(status));
				break;
			}
			if (WIFSIGNALED(status)) {
				PRINT_INFO("Child exit due to signal %d\n", WTERMSIG(status));
				break;
			}
			if (!WIFSTOPPED(status)) {
				PRINT_INFO("wait() returned unhandled status 0x%x\n", status);
				break;
			}

			//child stop signal: WSTOPSIG(status): SIGTRAP

			ptrace(PTRACE_GETREGS, pid, 0, &regs);
			syscall_id = regs.orig_rax;
			struct syscall_mod trap{pid, syscall_id, &regs};

			what_do = redirect_decision(&trap);

			if (what_do.redirect) {
				//replace syscall id with some syscall that does no i/o etc:
				regs.orig_rax = HARMLESS_SYSCALL;
				ptrace(PTRACE_SETREGS, pid, 0, &regs);
				regs.orig_rax = syscall_id;
			}

			//let the syscall run, wait for syscall exit:
			//TODO: patch kernel to allow syscall skip
			ptrace(PTRACE_SYSCALL, pid, 0, 0);
			wait(&status);

			if (what_do.redirect) {
				syscall_inject(&trap);
				if (trap.set_regs) {
					ptrace(PTRACE_SETREGS, pid, 0, trap.regs);
				}
			}
		}

		terminate_connection();
	}

	return 0;
}


int parse_args(int argc, char **argv, int *call_argc, char **&call_argv) {
	int ret = 0;
	int c;
	int digit_optind = 0;

	while (1) {
		int this_option_optind = optind ? optind : 1;
		int option_index = 0;
		static struct option long_options[] = {
			{"help",    no_argument,       0,  'h' },
			{0,         0,                 0,  0 }
		};

		c = getopt_long(argc, argv, "h", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			printf("option %s", long_options[option_index].name);
			if (optarg) {
				printf(" = %s", optarg);
			}
			printf("\n");
			break;

		case 'h':
			printf("you might find some help here someday.\n");
			ret = 1;
			break;

		case '?':
			break;

		default:
			printf("?? getopt returned character code 0%o ??\n", c);
		}
	}

	if (optind < argc) {
		printf("will run: ");
		*call_argc = argc - optind;

		//where the arg ptrs will be stored
		call_argv = (char **)malloc(sizeof(char *) * (*call_argc + 1));

		for (int i = 0; optind < argc; optind++, i++) {
			//store arg ptrs
			call_argv[i] = argv[optind];
			printf("%s ", argv[optind]);
		}
		printf("\n");

		call_argv[*call_argc] = NULL;
	} else {
		printf("usage: %s [options] <program> <arg 0> <arg n>\n", argv[0]);
		ret = 2;
	}

	return ret;
}


int main(int argc, char **argv) {
	int ret = 0;

	char **call_argv = nullptr;
	int call_argc;

	if (0 == parse_args(argc, argv, &call_argc, call_argv)) {
		try {
			run(call_argc, call_argv);
		} catch (util::Error e) {
			printf("ERROR: %s\n", e.str());
			ret = 1;
		}
	}
	else {
		ret = 1;
	}

	if (call_argv != nullptr) {
		free(call_argv);
	}

	return ret;
}
