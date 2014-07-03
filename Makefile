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

all: emulator kernel arrshell libinject

kernel:
	make -j $(corecount) -C $(kernel)/ modules SUBDIRS=arch/x86/kvm/

emulator:
	make CFLAGS=$(CFLAGS) -j $(corecount) -C $(emulator)/

arrshell:
	make -C arrshell

libinject:
	make -C libinject

configure:
	(cd $(emulator)/ && CFLAGS=$(CFLAGS) ./configure --python=$(shell which python3) --target-list=x86_64-softmmu --enable-kvm)

run: kernel emulator
	./run

.PHONY: configure run arrshell libinject


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

#(syscalls='getdents open read stat'; cd ~/devel/x-shell/x-tier/ && make -C ./parser/linux/ && for f in $syscalls; do strip -d modules/linux/syscalls/$f/$f.ko; ./parser/linux/inject-parser -i $f -o /tmp/$f.inject -d wrapper/linux64/ -w wrapper/linux64/wrappers.txt modules/linux/syscalls/$f/$f.ko; done

syscalls = getdents open read stat
injects = $(patsubst %,%.inject,$(syscalls))

%.inject: x-tier/modules/syscalls/%/%.ko $(parser)
	$(parser) -o $@ -d $(WRAPPER_DIR) -w $(WRAPPER_DIR)/wrappers.txt $<

inject_files: $(parser)
	make -C x-tier/modules/linux


