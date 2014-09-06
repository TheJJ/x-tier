wrappers = sys_open sys_close sys_read sys_getdents sys_lseek sys_stat XTIER_vfs_stat cp_new_stat sys_newuname XTIER_vfs_lstat sys_write sys_rename sys_unlink

wrappers_elf = $(patsubst %,%.elf,$(wrappers))

all: $(wrappers_elf) wrappers.txt

%.elf: %.c
	$(CC) -g -std=c99 -static -nostartfiles -Wall -Wextra -pedantic $< -o $@

wrappers.txt:
	@rm -f $@
	@echo creating wrapper def file $@...
	@for wr in $(wrappers); do echo $${wr} >> $@; done

clean:
	rm -f $(wrappers_elf) *.o *.so

.PHONY: all clean wrappers.txt
