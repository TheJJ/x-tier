# x-shell makefile
#
# compile the kernel and qemu

emulator  = qemu
kernel    = linux
corecount = $(shell nproc)

CFLAGS="-O2 -g -march=native"
CXXFLAGS=$(CFLAGS)

parser_path = x-tier/parser/linux/
parser = $(parser_path)/inject-parser

all: emulator kernel arrshell

kernel:
	make -j $(corecount) -C $(kernel)/ modules SUBDIRS=arch/x86/kvm/

emulator:
	make CFLAGS=$(CFLAGS) -j $(corecount) -C $(emulator)/

arrshell:
	make -C arrshell

configure:
	(cd $(emulator)/ && CFLAGS=$(CFLAGS) ./configure --python=$(shell which python3) --target-list=x86_64-softmmu --enable-kvm)

run: kernel emulator testmodule
	./run

.PHONY: $(parser)
$(parser):
	make -C $(parser_path)

testmodule: $(parser)
	$(parser) -o /tmp/lsmod.inject -d x-tier/wrapper/linux64/ -w x-tier/parser/linux/wrapper.txt x-tier/modules/linux/modules/default/lsmod.ko

.PHONY: configure run testmodule arrshell
