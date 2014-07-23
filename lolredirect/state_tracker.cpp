#include "state_tracker.h"

#include <sys/reg.h>
#include <sys/syscall.h>
#include <cstring>

#include "syscall_utils.h"
#include "x-inject.h"


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
	case SYS_chdir:
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
	case SYS_fchdir:
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

			const char *substrings[] = {
				"NOFWD",
				"terminfo",
				"locale",
			};

			bool host_path = false;

			for (auto &prefix : prefixes) {
				if (0 == util::strpcmp(path, prefix)) {
					host_path = true;
					break;
				}
			}

			if (not host_path) {
				for (auto &substr : substrings) {
					if (NULL != strstr(path, substr)) {
						host_path = true;
						break;
					}
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
