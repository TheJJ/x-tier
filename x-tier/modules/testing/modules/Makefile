MODNAME = lsmod

EXTRA_CFLAGS += -mcmodel=large
obj-m = $(MODNAME).o
KDIR :=  /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

.PHONY: all
all:
	make -C $(KDIR) M=$(PWD) modules

.PHONY: clean
clean:
	make -C $(KDIR) M=$(PWD) clean

.PHONY: inject
inject: all $(MODNAME).inject

$(MODNAME).inject: $(MODNAME).ko
	make -C ../../../../parser/linux/ create MODULE=$<
