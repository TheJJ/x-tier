MODULES=syscalls testing

all: $(MODULES)

$(MODULES):
	@echo "Beware: these modules have to be compiled on the guest!"
	make -C $@/

.PHONY: all $(MODULES)
