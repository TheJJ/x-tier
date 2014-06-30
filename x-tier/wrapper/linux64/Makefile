wrappers = sys_open sys_close sys_read sys_getdents sys_lseek sys_stat XTIER_vfs_stat cp_new_stat

all: $(patsubst %,%.elf,$(wrappers)) wrappers.txt

%.elf: %.c
	$(CC) -static -nostartfiles $< -o $@

wrappers.txt:
	@rm -f $@
	@echo creating wrapper def file $@...
	@for wr in $(wrappers); do echo $${wr} >> $@; done

clean:
	rm -f $(wrappers) *.o *.so

.PHONY: all clean wrappers.txt
