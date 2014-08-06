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
bool on_stat(syscall_mod *trap, bool do_fdlookup);
bool on_lseek(syscall_mod *trap);
bool on_fcntl(syscall_mod *trap);
bool on_chdir(syscall_mod *trap, bool do_fdlookup);

#endif //_SYSCALL_HANDLER_H_
