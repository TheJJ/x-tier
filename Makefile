# x-shell makefile
#
# compile the kernel and qemu

emulator  = qemu
kernel    = linux
corecount = $(shell nproc)

all: emulator kernel

kernel:
	make -j $(corecount) -C $(kernel)/

emulator:
	make -j $(corecount) -C $(emulator)/

configure:
	(cd $(emulator)/ && ./configure --python=$(shell which python3) --target-list=x86_64-softmmu --enable-kvm)


.PHONY: configure run
