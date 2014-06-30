SYSCALLS=getdents open read stat

all: $(SYSCALLS)

$(SYSCALLS):
	make -C $@/

.PHONY: all $(SYSCALLS)
