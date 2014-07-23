#ifndef _STATE_TRACKER_H_
#define _STATE_TRACKER_H_

#include <string>

#include "lolredirect.h"

struct file_state {
	int fd;            // emulated file descriptor id
	std::string path;  // filename
	int flags;         // file open flags
	int mode;          // file open mode
	int close_on_exec; // automatically close this file when exec* is run
	ssize_t pos;       // current seek position
	bool getdents;     // getdents is currently in progress
};

struct process_state {
	std::string cwd;
};

#define FILE_DESCRIPTOR_OFFSET 42
extern unsigned int next_free_fd;

struct decision redirect_decision(struct syscall_mod *trap);

#endif //_STATE_TRACKER_H_
