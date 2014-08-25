SYSCALLS=getdents open read stat uname

all: $(SYSCALLS)

$(SYSCALLS):
	make -C $@/

.PHONY: all $(SYSCALLS)
