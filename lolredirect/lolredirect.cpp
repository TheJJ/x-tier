#include "lolredirect.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "syscall_handler.h"
#include "syscall_utils.h"
#include "state_tracker.h"

#include "x-inject.h"

#define HARMLESS_SYSCALL SYS_getuid


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
		printf("usage: %s [options] <program> <arg 0> <arg n...>\n", argv[0]);
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
