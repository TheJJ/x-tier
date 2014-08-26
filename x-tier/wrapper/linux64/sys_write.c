
#include "../../../tmp/sysmap.h"  // kernel symbol names
#include <stdint.h>

/**
 * generated with: './wrapper_generator.py' 'sys_write' 'lnx_sys_write' 'int fd' 'in char[count] buf' 'int count'
 */

// variables to be patches by injection shellcode, in .text section
unsigned long kernel_esp     __attribute__ ((section (".text"))) = 0;
unsigned long target_address __attribute__ ((section (".text"))) = 0;

long sys_write(int64_t fd, char *buf, int64_t count) {
	unsigned long esp_offset = 0;   // kernel stack allocation size
	unsigned long return_value = 0; // function call return value

	int i = 0;


	// === argument: char buf[count]

	char *buf_stack_buffer = (char *)(((char *)kernel_esp) - (esp_offset + count));
	for (i = 0; i < count; i++) {
		buf_stack_buffer[i] = buf[i];
	}

	esp_offset += count;


	// store the prepared arguments to registers
	// then ask the hypervisor to perform the external function call.
	__asm__ volatile(
		"mov $" SYMADDR_STR(lnx_sys_write) ", %%rbx;" // RBX gets jump target

		"mov %2, %%rdi;"  // arg 0
		"mov %3, %%rsi;"  // arg 1
		"mov %4, %%rdx;"  // arg 2

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
		"m"(fd), "m"(buf_stack_buffer), "m"(count),
		"m"(return_value)
		:
		"rax", "rbx", "rdi", "rsi", "rdx"
	);



	// return to caller
	return return_value;
}

