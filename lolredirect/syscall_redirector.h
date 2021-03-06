#ifndef _SYSCALL_HANDLER_H_
#define _SYSCALL_HANDLER_H_

#include "lolredirect.h"
#include "state_tracker.h"

struct syscall_mod;

bool syscall_redirect(syscall_mod *trap);

bool on_open(syscall_mod *trap, bool openat=false);
bool on_read(syscall_mod *trap);
bool on_close(syscall_mod *trap);
bool on_getdents(syscall_mod *trap);
bool on_stat(syscall_mod *trap, bool do_fdlookup, bool do_at, bool do_lstat);
bool on_lseek(syscall_mod *trap);
bool on_fcntl(syscall_mod *trap);
bool on_chdir(syscall_mod *trap, bool do_fdlookup);
bool on_getcwd(syscall_mod *trap);
bool on_uname(syscall_mod *trap);
bool on_dup(syscall_mod *trap, int dupn);
bool on_readlink(syscall_mod *trap, bool do_at);
bool on_getxattr(syscall_mod *trap);
bool on_lgetxattr(syscall_mod *trap);
bool on_clock_gettime(syscall_mod *trap);
bool on_clock_getres(syscall_mod *trap);
bool on_statfs(syscall_mod *trap);

bool on_write(syscall_mod *trap);
bool on_unlink(syscall_mod *trap);
bool on_rename(syscall_mod *trap);

#endif //_SYSCALL_HANDLER_H_
