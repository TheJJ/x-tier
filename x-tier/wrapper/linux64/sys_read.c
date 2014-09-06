
#include "../../../tmp/sysmap.h"  // kernel symbol names

#include <stdint.h>

/**
 * generated with: './wrapper_generator.py' 'sys_read' 'lnx_sys_read' 'int fd' 'ret char[bufsize] buf' 'long bufsize'
 */

// variables to be patches by injection shellcode, in .text section
unsigned long kernel_esp     __attribute__ ((section (".text"))) = 0;
unsigned long target_address __attribute__ ((section (".text"))) = 0;

int64_t sys_read(int fd, char *buf, long bufsize) {
	unsigned long esp_offset = 0;   // kernel stack allocation size
	int64_t return_value = 0; // function call return value

	int64_t i = 0;


	char *buf_stack_buffer = (char *)(kernel_esp - (esp_offset + bufsize));
	esp_offset += bufsize; // reserve space for buf


	// store the prepared arguments to registers
	// then ask the hypervisor to perform the external function call.
	__asm__ volatile(
		"mov $" SYMADDR_STR(lnx_sys_read) ", %%rbx;" // RBX gets jump target

		"mov $0, %%rdi;"  // zero arg 0
		"mov %2, %%rdi;"  // prepare arg 0
		"mov $0, %%rsi;"  // zero arg 1
		"mov %3, %%rsi;"  // prepare arg 1
		"mov $0, %%rdx;"  // zero arg 2
		"mov %4, %%rdx;"  // prepare arg 2

		"mov  %0, %%rax;"      // store original kernel_stack into rax
		"sub  %1, %%rax;"      // decrease stack ptr by allocation amount
		"push %%rbp;"          // save EBP
		"mov  %%rsp, %%rbp;"   // save stack pointer
		"mov  %%rax, %%rsp;"   // set stack pointer
		"mov  $42, %%rax;"     // select `command` as interrupt handler in RAX
		"int  $42;"            // send interrupt, hypercall happens here
		"mov  %%rbp, %%rsp;"   // restore RSP
		"pop  %%rbp;"          // restore RBP

		"mov  %%rax, %5;"      // save return value
		:
		:
		"r"(kernel_esp),
		"r"(esp_offset),
		"m"(fd), "m"(buf_stack_buffer), "m"(bufsize),
		"m"(return_value)
		:
		"rax", "rbx", "rdi", "rsi", "rdx"
	);


	for (i = 0; i < (int64_t)return_value; i++) {
		buf[i] = buf_stack_buffer[i];
	}


	// return to caller
	return return_value;
}
