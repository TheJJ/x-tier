# x-shell makefile
#
# compile the kernel and qemu

emulator  = qemu
kernel    = linux
corecount = $(shell nproc)

CFLAGS="-O2 -g -march=native"
CXXFLAGS=$(CFLAGS)

parser_path  = x-tier/parser/linux/
parser       = $(parser_path)/inject-parser
wrapper_path = x-tier/wrapper/linux64/

#pass sysmap filename as parameter pls
SYSMAP = /pass/me/pls

all: emulator kernel arrshell

kernel:
	make -j $(corecount) -C $(kernel)/ modules SUBDIRS=arch/x86/kvm/

emulator:
	make CFLAGS=$(CFLAGS) -j $(corecount) -C $(emulator)/

arrshell:
	make -C arrshell

configure:
	(cd $(emulator)/ && CFLAGS=$(CFLAGS) ./configure --python=$(shell which python3) --target-list=x86_64-softmmu --enable-kvm)

run: kernel emulator
	./run

.PHONY: configure run arrshell


tmp:
	@mkdir -p tmp/

tmp/sysmap.h: util/sysmap.py tmp
	./$< --create-strings $(SYSMAP) $@

.PHONY: $(parser)
$(parser): wrappers
	make -C $(parser_path)

.PHONY: wrappers
wrappers: tmp/sysmap.h
	make -C $(wrapper_path)


/tmp/lsmod.inject: $(parser)
	$< -o $@ -d $(WRAPPER_DIR) -w $(WRAPPER_DIR)/wrappers.txt x-tier/modules/linux/modules/lsmod.ko
