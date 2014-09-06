
#include "../../../tmp/sysmap.h"  // kernel symbol names

#include <stdint.h>
#include <asm/stat.h>

/**
 * generated with: './wrapper_generator.py' '-i' '<asm/stat.h>' 'sys_stat' 'lnx_sys_stat' 'in char *filename' 'out char*[sizeof(struct __old_kernel_stat)] statbuf'
 */

// variables to be patches by injection shellcode, in .text section
unsigned long kernel_esp     __attribute__ ((section (".text"))) = 0;
unsigned long target_address __attribute__ ((section (".text"))) = 0;

int64_t sys_stat(char *filename, char *statbuf) {
	unsigned long esp_offset = 0;   // kernel stack allocation size
	int64_t return_value = 0; // function call return value

	int64_t i = 0;


	// === argument: char *filename
	int filename_length = 1; // including \0
	char *filename_len_tmp = (char *)filename;

	while ((*filename_len_tmp) != '\0') {
		filename_length  += 1;
		filename_len_tmp += 1;
	}

	
	char *filename_stack_buffer = (char *)(kernel_esp - (esp_offset + filename_length));
	for (i = 0; i < (int64_t)filename_length; i++) {
		filename_stack_buffer[i] = filename[i];
	}

	esp_offset += filename_length;
	// ====

	char *statbuf_stack_buffer = (char *)(kernel_esp - (esp_offset + sizeof(struct __old_kernel_stat)));
	esp_offset += sizeof(struct __old_kernel_stat); // reserve space for statbuf


	// store the prepared arguments to registers
	// then ask the hypervisor to perform the external function call.
	__asm__ volatile(
		"mov $" SYMADDR_STR(lnx_sys_stat) ", %%rbx;" // RBX gets jump target

		"mov $0, %%rdi;"  // zero arg 0
		"mov %2, %%rdi;"  // prepare arg 0
		"mov $0, %%rsi;"  // zero arg 1
		"mov %3, %%rsi;"  // prepare arg 1

		"mov  %0, %%rax;"      // store original kernel_stack into rax
		"sub  %1, %%rax;"      // decrease stack ptr by allocation amount
		"push %%rbp;"          // save EBP
		"mov  %%rsp, %%rbp;"   // save stack pointer
		"mov  %%rax, %%rsp;"   // set stack pointer
		"mov  $42, %%rax;"     // select `command` as interrupt handler in RAX
		"int  $42;"            // send interrupt, hypercall happens here
		"mov  %%rbp, %%rsp;"   // restore RSP
		"pop  %%rbp;"          // restore RBP

		"mov  %%rax, %4;"      // save return value
		:
		:
		"r"(kernel_esp),
		"r"(esp_offset),
		"m"(filename_stack_buffer), "m"(statbuf_stack_buffer),
		"m"(return_value)
		:
		"rax", "rbx", "rdi", "rsi"
	);


	for (i = 0; i < (int64_t)sizeof(struct __old_kernel_stat); i++) {
		statbuf[i] = statbuf_stack_buffer[i];
	}


	// return to caller
	return return_value;
}
