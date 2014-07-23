#ifndef _SYSCALL_HANDLER_H_
#define _SYSCALL_HANDLER_H_

bool on_open(struct syscall_mod *trap, bool openat=false);
bool on_read(struct syscall_mod *trap);
bool on_close(struct syscall_mod *trap);
bool on_getdents(struct syscall_mod *trap);
bool on_stat(struct syscall_mod *trap, bool do_fdlookup);
bool on_lseek(struct syscall_mod *trap);
bool on_fcntl(struct syscall_mod *trap);
bool on_chdir(struct syscall_mod *trap, bool do_fdlookup);

#endif //_SYSCALL_HANDLER_H_
