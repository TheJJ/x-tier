.PHONY: all
all: inject-parser

CFLAGS=-g -O0 -Wall -Werror -std=c99
C=$(CC)

inject-parser: parser.o shellcode_bin.o printf_shellcode_bin.o
	$(C) $(CFLAGS) -o $@ -lelf $^

parser.o: parser.c
	$(C) $(CFLAGS) -o $@ -c $<

shellcode.bin: shellcode.asm
	nasm -f bin -o $@ -l shellcode.lst $<

printf_shellcode.bin: printf_shellcode.asm
	nasm -f bin -o $@ -l printf_shellcode.lst $<

shellcode_bin.o: shellcode.bin
	ld -r -b binary -o $@ $<

printf_shellcode_bin.o: printf_shellcode.bin
	ld -r -b binary -o $@ $<

.PHONY: clean
clean:
	rm -f *.o inject-parser *shellcode.lst *.bin
