CMD = /bin/ls /bin


all: arrpreter

pin/pin:
	@echo "download pin!"

arrpreter:
	make -C arrpreter

run: pin/pin arrpreter
	cd arrpreter && ../pin/pin -t arrpreter.so -monitorPort 8998 -- $(CMD)

clean:
	make -C arrpreter clean

.PHONY: all run clean arrpreter
