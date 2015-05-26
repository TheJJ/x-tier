
#include "../../../tmp/sysmap.h"  // kernel symbol names

#include <stdint.h>

/**
 * generated with: './wrapper_generator.py' 'sys_close' 'lnx_sys_close' 'unsigned int fd'
 */

// variables to be patches by injection shellcode, in .text section
unsigned long kernel_esp     __attribute__ ((section (".text"))) = 0;
unsigned long target_address __attribute__ ((section (".text"))) = 0;

int64_t sys_close(unsigned int fd) {
	unsigned long esp_offset = 0;   // kernel stack allocation size
	int64_t return_value = 0; // function call return value




	// store the prepared arguments to registers
	// then ask the hypervisor to perform the external function call.
	__asm__ volatile(
		"mov $" SYMADDR_STR(lnx_sys_close) ", %%rbx;" // RBX gets jump target

		"mov $0, %%rdi;"  // zero arg 0
		"mov %2, %%rdi;"  // prepare arg 0

		"mov  %0, %%rax;"      // store original kernel_stack into rax
		"sub  %1, %%rax;"      // decrease stack ptr by allocation amount
		"push %%rbp;"          // save EBP
		"mov  %%rsp, %%rbp;"   // save stack pointer
		"mov  %%rax, %%rsp;"   // set stack pointer
		"mov  $42, %%rax;"     // select `command` as interrupt handler in RAX
		"int  $42;"            // send interrupt, hypercall happens here
		"mov  %%rbp, %%rsp;"   // restore RSP
		"pop  %%rbp;"          // restore RBP

		"mov  %%rax, %3;"      // save return value
		:
		:
		"r"(kernel_esp),
		"r"(esp_offset),
		"m"(fd),
		"m"(return_value)
		:
		"rax", "rbx", "rdi"
	);



	// return to caller
	return return_value;
}
