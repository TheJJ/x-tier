.PHONY: all
all: inject-parser

CFLAGS=-g -O0

inject-parser: parser.o shellcode_bin.o
	$(CC) $(CFLAGS) -o $@ -lelf $^

parser.o: parser.c
	$(CC) $(CFLAGS) -o $@ -c $<

shellcode.bin: shellcode.asm
	nasm -f bin -o $@ -l shellcode.lst $<

shellcode_bin.o: shellcode.bin
	ld -r -b binary -o $@ $<

.PHONY: clean
clean:
	rm -f *.o inject-parser shellcode.lst *.bin
