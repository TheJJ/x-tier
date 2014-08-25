SYSCALLS=getdents open read stat uname lstat

all: $(SYSCALLS)

$(SYSCALLS):
	make -C $@/

.PHONY: all $(SYSCALLS)
