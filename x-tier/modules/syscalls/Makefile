SYSCALLS=getdents open read stat uname lstat write

all: $(SYSCALLS)

$(SYSCALLS):
	make -C $@/

.PHONY: all $(SYSCALLS)
