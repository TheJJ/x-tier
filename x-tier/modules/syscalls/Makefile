SYSCALLS=getdents open read stat uname lstat write unlink rename

all: $(SYSCALLS)

$(SYSCALLS):
	make -C $@/

.PHONY: all $(SYSCALLS)
