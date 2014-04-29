all: inject-parser

inject-parser: parser.o shellcode_bin.o
	gcc -o $@ -lelf $^

parser.o: parser.c
	gcc -o $@ -c $<

shellcode.o: shellcode.asm
	nasm -f elf64 -o $@ -l shellcode.lst $<

shellcode_bin.o: shellcode.o
	ld -r -b binary -o $@ $<

clean:
	rm -f *.o inject-parser shellcode.lst
