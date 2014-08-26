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

#include "syscall_utils.h"

#include "x-inject.h"

#define HARMLESS_SYSCALL SYS_getuid

syscall_mod::syscall_mod(int pid, int syscall_id, struct user_regs_struct *regs, process_state *pstate)
	:
	pid(pid),
	syscall_id(syscall_id),
	set_regs(false),
	regs(regs),
	pstate(pstate)
{}

uint64_t *syscall_mod::get_arg_ptr(int arg_id) {
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

uint64_t syscall_mod::get_arg(int arg_id) {
	return *this->get_arg_ptr(arg_id);
}

void syscall_mod::set_arg(int arg_id, uint64_t val) {
	*this->get_arg_ptr(arg_id) = val;
	this->set_regs = true;
}

void syscall_mod::set_return(uint64_t val) {
	this->regs->rax = val;
	this->set_regs = true;
}

void syscall_mod::print_registers() {
	printf(
		"syscall %03d:\n"
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


int run(int argc, char **argv, std::string cwd) {
	int status = 0;

	int pid = fork();

	if (!pid) {
		PRINT_DEBUG("exec %s\n", argv[0]);

		ptrace(PTRACE_TRACEME, 0, 0, 0);
		execvp(argv[0], argv);
		PRINT_DEBUG("target exec fail'd!\n");
		return 1;
	}
	else {
		wait(&status);

		struct decision what_do;
		struct user_regs_struct regs;
		int syscall_id;

		struct process_state pstate{cwd, argc, argv};

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
			struct syscall_mod trap{pid, syscall_id, &regs, &pstate};

			what_do = pstate.redirect_decision(&trap);

			if (what_do.redirect) {
				//replace syscall id with some syscall that does no i/o etc:
				regs.orig_rax = HARMLESS_SYSCALL;
				ptrace(PTRACE_SETREGS, pid, 0, &regs);
				regs.orig_rax = syscall_id;
			}

			//let the syscall run, wait for syscall exit.
			//TODO: patch kernel to allow syscall skip
			ptrace(PTRACE_SYSCALL, pid, 0, 0);
			wait(&status);

			if (what_do.redirect) {
				syscall_redirect(&trap);
				if (trap.set_regs) {
					ptrace(PTRACE_SETREGS, pid, 0, trap.regs);
				}
			}

			pstate.syscall_id_previous = syscall_id;
		}

		PRINT_DEBUG("execution finished!\n");
		PRINT_DEBUG("syscall count:   %d\n", pstate.syscall_count);
		PRINT_DEBUG("host syscalls:   %d\n", pstate.host_syscall_count);
		PRINT_DEBUG("injection count: %d\n", pstate.redirect_syscall_count);

		terminate_connection();
	}

	return 0;
}


int parse_args(int argc, char **argv, int *call_argc, char **&call_argv, std::string *cwd) {
	int ret = 0;
	int c;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"help",        no_argument,    0,  'h' },
			{"cwd",   required_argument,    0,  'c' },
			{"port",  required_argument,    0,  'p' },
			{0,                       0,    0,   0 }
		};

		c = getopt_long(argc, argv, "hc:p:", long_options, &option_index);
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

		case 'c':
			//initial working directory
			*cwd = optarg;
			break;

		case 'p':
			printf("port argument not implemented yet!\n");
			break;

		case '?':
			return 1;
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
		printf("usage: %s [options] -- <program> <arg 0> <arg n...>\n", argv[0]);
		printf("   -h --help: display help\n");
		printf("   -c --cwd:  initial working directory (default: /)\n");
		ret = 2;
	}

	return ret;
}

int main(int argc, char **argv) {
	int ret = 0;

	char **call_argv = nullptr;
	int call_argc;
	std::string cwd = "/";

	if (0 == parse_args(argc, argv, &call_argc, call_argv, &cwd)) {
		try {
			run(call_argc, call_argv, cwd);
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
