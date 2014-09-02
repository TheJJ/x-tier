#include "state_tracker.h"

#include <linux/fcntl.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <cstring>
#include <vector>

#include "syscall_utils.h"
#include "util.h"
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


const char *redirect_reason_str(struct decision d) {
	redirect_reason r = d.reason;
	const char *ret;
	switch(r) {
	case redirect_reason::PATH:
		ret = "path";
		break;
	case redirect_reason::PATH_WHITELIST:
		ret = "whitelisted path";
		break;
	case redirect_reason::PATH_PREFIX:
		ret = "blacklisted path prefix";
		break;
	case redirect_reason::PATH_SUBSTRING:
		ret = "blacklisted path substring";
		break;
	case redirect_reason::FD:
		ret = "fd";
		break;
	case redirect_reason::UNHANDLED:
		ret = "unhandled syscall";
		break;
	case redirect_reason::INITSECTION:
		ret = "in program initsection";
		break;
	case redirect_reason::FORCED:
		ret = "redirection forced";
		break;
	default:
		ret = "unknown decision reason!";
		break;
	}
	return ret;
}


brk_state::brk_state(struct process_state *pstate)
	:
	pstate(pstate),
	last_brk_arg(-1)
{}

brk_state::~brk_state() {}

void brk_state::new_brk(int prev_syscall_id, ssize_t arg) {
	if (prev_syscall_id == SYS_brk) {
		if (arg != 0 && this->last_brk_arg == 0) {
			PRINT_DEBUG("program's init section is over now.\n");
			this->pstate->state = execution_section::MAIN_RUN;
		}
	}

	this->last_brk_arg = arg;
}

process_state::process_state(std::string cwd, int argc, char **argv)
	:
	cwd(cwd),
	argc(argc),
	argv(argv),
	state(execution_section::INIT),
	next_free_fd(FILE_DESCRIPTOR_OFFSET),
	syscall_id_previous(-1),
	brk_handler(this),
	host_syscall_count(0),
	redirect_syscall_count(0),
	syscall_count(0)
{}

process_state::~process_state() {
	std::vector<int> leaked_fds;
	for (auto file : this->files) {
		leaked_fds.push_back(file.first);
	}

	for (auto fdid : leaked_fds) {
		PRINT_DEBUG("LEAKED fd %d, closing...\n", fdid);
		this->close_fd(fdid);
	}
}

bool process_state::close_fd(int id) {
	auto search = this->files.find(id);
	if (search != this->files.end()) {
		struct file_state *fstate = search->second;
		PRINT_DEBUG("closing virtual fd %d..\n", id);
		fstate->fd_ids.erase(id);
		if (fstate->fd_ids.size() == 0) {
			PRINT_DEBUG("deleting fd %d state..\n", id);
			delete fstate;
		}
		this->files.erase(id);
		return true;
	} else {
		return false;
	}
}

struct decision process_state::redirect_decision(struct syscall_mod *trap) {
	if (print_syscalls) {
		trap->print_registers();
	}

	PRINT_DEBUG("encountered syscall %03d %s\n", trap->syscall_id, syscall_name(trap->syscall_id));

	char path[max_path_len];

	int fd = -1;
	int n  = 0;

	bool at_syscall = false;

	//disable redirection by default
	struct decision ret{false};
	bool possibly_redirect = true;

	//gather information about the trapped syscall
	switch (trap->syscall_id) {
	case SYS_open:
	case SYS_stat:
	case SYS_lstat:
	case SYS_chdir:
		n = util::tstrncpy(trap, path, (char *)trap->get_arg(0), max_path_len);
		break;

		// arg0 is a fd
	case SYS_write:
	case SYS_read:
	case SYS_close:
	case SYS_fstat:
	case SYS_lseek:
	case SYS_fcntl:
	case SYS_fadvise64:
	case SYS_getdents:
	case SYS_fchdir:
	case SYS_dup:
	case SYS_dup2:
	case SYS_dup3:
		fd = trap->get_arg(0);
		break;

	case SYS_openat:
	case SYS_newfstatat:
		at_syscall = true;
		fd = trap->get_arg(0);
		break;

	case SYS_brk:
		this->brk_handler.new_brk(this->syscall_id_previous, trap->get_arg(0));
		possibly_redirect = false;
		break;

		//unimplemented, but interesting syscalls:
	case SYS_clock_getres:
	case SYS_clock_gettime:
	case SYS_timer_gettime:
	case SYS_timer_getoverrun:
	case SYS_faccessat:
	case SYS_fchmodat:
	case SYS_fchownat:
	case SYS_futimesat:
	case SYS_ioctl:

	case SYS_getxattr:
	case SYS_lgetxattr:
	case SYS_fgetxattr:
	case SYS_setxattr:
	case SYS_lsetxattr:
	case SYS_fsetxattr:
	case SYS_removexattr:
	case SYS_lremovexattr:
	case SYS_fremovexattr:
	case SYS_listxattr:
	case SYS_llistxattr:
	case SYS_flistxattr:

	case SYS_linkat:
	case SYS_mkdirat:
	case SYS_mknodat:
	case SYS_readlink:
	case SYS_readlinkat:
	case SYS_readv:
	case SYS_renameat:
	case SYS_statfs:
	case SYS_fstatfs:
	case SYS_symlinkat:
	case SYS_unlinkat:
	case SYS_ustat:

	case SYS_getrusage:
	case SYS_capget:
	case SYS_gettimeofday:
	case SYS_getgroups:
	case SYS_getpriority:
	case SYS_getitimer:
	case SYS_get_kernel_syms:
	case SYS_get_mempolicy:
	case SYS_getcpu:

		possibly_redirect = false;
		break;

		//syscalls to redirect no matter what:
	case SYS_getcwd:
	case SYS_getuid:
	case SYS_getgid:
	case SYS_geteuid:
	case SYS_getegid:
	case SYS_getresgid:
	case SYS_getresuid:
	case SYS_uname:
	case SYS_unlink:
	case SYS_rename:
		ret.reason   = redirect_reason::FORCED;
		ret.redirect = true;
		break;

		//unknown syscall id
	default:
		possibly_redirect = false;
	}

	if (this->state != execution_section::MAIN_RUN) {
		possibly_redirect = false;
	}

	if (possibly_redirect && ret.redirect == false) {
		if (n > 0) {
			const char *prefixes[] = {
				"/usr/lib/",
				"/usr/lib64/",
				"/lib/",
				"/lib64/",
				"/proc/self/",
				"/dev/tty",
				"/dev/pts/",
				"/etc/ld.so.cache",
				"/usr/share/locale/",
				"/usr/share/terminfo/",
				"/etc/terminfo/",
			};

			const char *substrings[] = {
				"terminfo",
				"NOFWD",  // custom special-keyword
			};

			bool host_path  = false;
			bool guest_path = false;

			ret.reason = redirect_reason::PATH;

			//whitelist program invokation arguments
			if (not host_path and not guest_path) {
				for (int i = 1; i < this->argc; i++) {
					const char *arg = this->argv[i];

					if (0 == strcmp(arg, path)) {
						guest_path = true;
						ret.reason = redirect_reason::PATH_WHITELIST;
						break;
					}
				}
			}

			//compare for path prefixes
			if (not host_path and not guest_path) {
				for (auto &prefix : prefixes) {
					if (0 == util::strpcmp(path, prefix)) {
						host_path = true;
						ret.reason = redirect_reason::PATH_PREFIX;
						break;
					}
				}
			}

			//compare for any substring
			if (not host_path and not guest_path) {
				for (auto &substr : substrings) {
					if (NULL != strstr(path, substr)) {
						host_path = true;
						ret.reason = redirect_reason::PATH_SUBSTRING;
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
		}

		if (fd >= 0) {
			if (trap->pstate->files.find(fd) == trap->pstate->files.end()) {
				PRINT_DEBUG("\tfd %d on host.\n", fd);
				ret.redirect = false;
			}
			else {
				PRINT_DEBUG("\tfd %d on guest.\n", fd);
				ret.redirect = true;
			}
			ret.reason = redirect_reason::FD;
		}
		else if (at_syscall && fd == AT_FDCWD) {
			// special value that indicates we should open relative to cwd
			ret.redirect = true;
			ret.reason = redirect_reason::FD;
		};
	} else if (ret.redirect == false) {
		ret.reason   = redirect_reason::UNHANDLED;
	}

	trap->pstate->syscall_count += 1;

	const char *action;

	if (ret.redirect) {
		trap->pstate->redirect_syscall_count += 1;
		action = "REDIRECTING";
	}
	else if (trap->syscall_id >= 0) {
		trap->pstate->host_syscall_count += 1;
		action = "ON HOST    ";
	} else {
		throw util::Error("syscall negative: %d! wtf?!\n", trap->syscall_id);
	}

	const char *reason = redirect_reason_str(ret);
	PRINT_DEBUG("\t`-> syscall %s %03d %s: %s\n", action, trap->syscall_id, syscall_name(trap->syscall_id), reason);

	return ret;
}
