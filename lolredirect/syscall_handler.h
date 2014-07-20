#ifndef _SYSCALL_HANDLER_H_
#define _SYSCALL_HANDLER_H_

#include <string>

struct file_state {
	int fd;            // emulated file descriptor id
	std::string path;  // filename
	int flags;         // file open flags
	int mode;          // file open mode
	int close_on_exec; // automatically close this file when exec* is run
	ssize_t pos;       // current seek position
	bool getdents;     // getdents is currently in progress
};

#define FILE_DESCRIPTOR_OFFSET 42
extern unsigned int next_free_fd;



bool on_open(struct syscall_mod *trap, bool openat=false);
bool on_read(struct syscall_mod *trap);
bool on_close(struct syscall_mod *trap);
bool on_getdents(struct syscall_mod *trap);
bool on_stat(struct syscall_mod *trap, bool do_fdlookup);
bool on_lseek(struct syscall_mod *trap);
bool on_fcntl(struct syscall_mod *trap);



#endif //_SYSCALL_HANDLER_H_
