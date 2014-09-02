EXTRA_CFLAGS += -mcmodel=large -fno-stack-protector
obj-m = rename.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean

