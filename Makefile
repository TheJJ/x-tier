# x-tier makefile
#
# compile the kernel and qemu

emulator  = qemu
kernel    = /usr/src/linux-git
corecount = $(shell nproc)

CFLAGS="-O2 -g -march=native"
CXXFLAGS=$(CFLAGS)

parser_path  = libinject/parser/linux/
parser       = $(parser_path)/inject-parser
wrapper_path = x-tier/wrapper/linux64/

#pass sysmap filename as parameter pls
SYSMAP = /pass/me/pls

all: emulator kernel libinject lolredirect

kernel:
	make -j $(corecount) -C $(kernel)/ modules SUBDIRS=arch/x86/kvm/

emulator:
	make CFLAGS=$(CFLAGS) -j $(corecount) -C $(emulator)/

arrshell:
	make -C arrshell

libinject:
	make -C libinject

lolredirect:
	make -C lolredirect

configure:
	(cd $(emulator)/ && CFLAGS=$(CFLAGS) ./configure --python=$(shell which python3) --target-list=x86_64-softmmu --enable-kvm)

run: kernel emulator
	./run

.PHONY: configure run arrshell libinject lolredirect


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

syscalls = getdents open read stat
injects = $(patsubst %,%.inject,$(syscalls))

%.inject: x-tier/modules/syscalls/%/%.ko $(parser)
	$(parser) -o $@ -d $(WRAPPER_DIR) -w $(WRAPPER_DIR)/wrappers.txt $<

inject_files: $(parser)
	make -C x-tier/modules/linux


