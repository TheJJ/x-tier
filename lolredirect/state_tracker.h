#ifndef _STATE_TRACKER_H_
#define _STATE_TRACKER_H_

#include <string>
#include <unordered_map>

#include "lolredirect.h"
#include "syscall_redirector.h"

//fd id of files opened in the guest
#define FILE_DESCRIPTOR_OFFSET 1000

enum class execution_section {
	INIT,
	MAIN_RUN,
};

enum class redirect_reason {
	PATH,
	FD,
	UNHANDLED,
	INITSECTION,
	FORCED,
};

const char *redirect_reason_str(redirect_reason r);

struct decision {
	decision() : redirect(false) {};
	decision(bool def) : redirect(def) {};
	bool redirect;
	redirect_reason reason;
};


struct file_state {
	int fd;            // emulated file descriptor id
	std::string path;  // filename
	int flags;         // file open flags
	int mode;          // file open mode
	int close_on_exec; // automatically close this file when exec* is run
	ssize_t pos;       // current seek position
	bool getdents;     // getdents is currently in progress
};

struct brk_state {
	brk_state(struct process_state *pstate);
	~brk_state();

	struct process_state *pstate;
	ssize_t last_brk_arg;

	void new_brk(int prev_syscall_id, ssize_t arg);
};

struct process_state {
	process_state(std::string cwd, int argc, char **argv);
	~process_state();

	std::string cwd;
	int argc;
	char **argv;
	execution_section state;
	unsigned int next_free_fd;
	std::unordered_map<int, struct file_state> files;

	int syscall_id_previous;
	struct brk_state brk_handler;

	int host_syscall_count;
	int redirect_syscall_count;
	int syscall_count;

	struct decision redirect_decision(struct syscall_mod *trap);
};


#endif //_STATE_TRACKER_H_
