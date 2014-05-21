;nasm -f elf64 -l shellcode.lst shellcode.asm
BITS 64
	SECTION .text
	global main

main:
	jmp start

strcmp:
	pop rax              ; ret addr
	pop rcx              ; len(symbolname)
	pop rdi              ; *symbolname
	push rax             ; ret addr

	mov rsi, [rbx+0x8]
	repe cmpsb           ; [rsi],[rdi]
	mov rax, 0
	jne strcmpret
	mov rax, [rbx]

strcmpret:
	ret

patcher:
	mov r8, [rbp+8]      ; counter
	mov r9, rbp

patchloop:
	add r9, 16
	test r8, r8          ; if count == 0
	jz endpatcher
	dec r8

	mov rax, rbp         ; baseaddr
	add rax, [r9]        ; addr where to write
	mov rbx, rbp         ; baseaddr
	add rbx, [r9+8]      ; addr what to write
	mov [rax], rbx
	jmp patchloop

endpatcher:
	mov rax, r9          ; return pointer to next data segment
	ret

esppatcher:
	pop rax           ; ret addr
	pop rdx           ; distance to our data
	pop rcx           ; ESP value
	push rax          ; ret addr
	push rbp          ; saving rbp
	add rbp, rdx      ; pointing after the patch stack

	mov r8, [rbp]      ; counter
	mov r9, rbp

esppatchloop:
	add r9, 8
	test r8, r8          ; if count == 0
	jz espendpatcher
	dec r8

	mov rax, rbp         ; segmentaddr
	sub rax, rdx         ; baseaddr = segmentaddr - distance
	add rax, [r9]        ; addr where to write
	mov [rax], rcx       ; write ESP
	jmp esppatchloop

espendpatcher:
	mov rax, r9          ; return pointer to next data segment
	pop rbp              ; Restoring rbp
	ret

symbolpatcher:
	pop rax           ; ret addr
	pop rdx           ; distance to our data
	push rax          ; ret addr
	push rbp          ; saving rbp

	add rbp, rdx      ; pointing after the patch stack
	mov rbx, [rbp]    ; Begin ; End = [rbp+8]

suchloop:
	mov r8, [rbp+16]  ; count symbols
	lea r15, [rbp+24] ; *(len of first symbol)

vergleichloop:
	test r8, r8       ; if countsymbols == 0
	jz endvergleich
	dec r8
	mov r9, [r15]     ; len of symbol
	add r15, 8        ; next pointer
	lea r10, [r15]    ; addr of symbolname
	add r15, r9       ; *r15 = addr to be patched
	push r10
	push r9
	call strcmp
	test rax, rax
	jz nosymbolfound
	mov r9, [r15]  ; addr to write
	add r9, rbp    ; segmentpointer
	sub r9, rdx    ; distance to base
	mov [r9], rax  ; writing addr of symbol to destination

nosymbolfound:
	add r15, 0x8
	jmp vergleichloop

endvergleich:
	add rbx, 0x10     ; next list_head
	cmp rbx, [rbp+8]  ; if begin == end
	je endsymbolpatcher
	jmp suchloop

endsymbolpatcher:
	pop rbp
	ret

saveregisters:
	add rsp, 0x8     ; retun value
	add rsp, 0x10    ; 2*8 values auf stack
	add rsp, 0x78    ; 15*8 register
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
	push rbp
	push rdi
	push rsi
	push rdx
	push rcx
	push rbx
	push rax
	sub rsp, 0x10    ; 2*8 values auf stack
	sub rsp, 0x8     ; return valueyy
	ret

restoreregisters:
	add rsp, 0x8     ; retun value
	add rsp, 0x8     ; 1*8 value auf stack
	pop rax
	pop rbx
	pop rcx
	pop rdx
	pop rsi
	pop rdi
	pop rbp
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	sub rsp, 0x78      ; 15*8 registers
	sub rsp, 0x8       ; 1*8 value auf stack
	sub rsp, 0x8       ; return valueyy
	ret

sc:
	call saveregisters ; Alle Register speichern
	pop rbp            ; our base poiting to our data
	pop r12            ; original ESP Value which is pushed into the stack by the hypervisor
	mov r11, [rbp]     ; entrypoint of module
	call patcher
	mov rbx, rax       ; pointer to next symbol data
	sub rbx, rbp       ; distance to next data

	push r12           ; original ESP value
	push rbx           ; distance to data
	call esppatcher
	mov rbx, rax       ; pointer to next symbol data
	sub rbx, rbp       ; distance to symbol data

	push rbx
	call symbolpatcher

exit:
	nop
	mov rax, r11       ; entrypointoffset
	add rax, rbp       ; add base offset
	push rax           ; addr to call
	call restoreregisters    ; Register zuruecksetzen
	pop rax            ; ein ret wuerde auch machen, aber problem ist der VMI exit
	add rsp, 800       ; Constant offset to stackEND (=original stack)
	call rax
	hlt                ; VMI exit

	nop

start:
	call sc

stack:


; Aufbau:
; entrypoint
; patch_count
; patch_add_off
; patch_val_off
; ...
; esppatch_count
; esppatch_add_off
; ...
; __start___ksymtab
; __stop___ksymtab
; count symbols
; len(printk)
; printk\0
; addtowrite printk
; ...
