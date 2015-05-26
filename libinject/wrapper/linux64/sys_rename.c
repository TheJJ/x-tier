
#include "../../../tmp/sysmap.h"  // kernel symbol names

#include <stdint.h>

/**
 * generated with: './wrapper_generator.py' 'sys_rename' 'lnx_sys_rename' 'in char *oldname' 'in char *newname'
 */

// variables to be patches by injection shellcode, in .text section
unsigned long kernel_esp     __attribute__ ((section (".text"))) = 0;
unsigned long target_address __attribute__ ((section (".text"))) = 0;

int64_t sys_rename(char *oldname, char *newname) {
	unsigned long esp_offset = 0;   // kernel stack allocation size
	int64_t return_value = 0; // function call return value

	int64_t i = 0;


	// === argument: char *oldname
	int oldname_length = 1; // including \0
	char *oldname_len_tmp = (char *)oldname;

	while ((*oldname_len_tmp) != '\0') {
		oldname_length  += 1;
		oldname_len_tmp += 1;
	}

	
	char *oldname_stack_buffer = (char *)(kernel_esp - (esp_offset + oldname_length));
	for (i = 0; i < (int64_t)oldname_length; i++) {
		oldname_stack_buffer[i] = oldname[i];
	}

	esp_offset += oldname_length;
	// ====

	// === argument: char *newname
	int newname_length = 1; // including \0
	char *newname_len_tmp = (char *)newname;

	while ((*newname_len_tmp) != '\0') {
		newname_length  += 1;
		newname_len_tmp += 1;
	}

	
	char *newname_stack_buffer = (char *)(kernel_esp - (esp_offset + newname_length));
	for (i = 0; i < (int64_t)newname_length; i++) {
		newname_stack_buffer[i] = newname[i];
	}

	esp_offset += newname_length;
	// ====


	// store the prepared arguments to registers
	// then ask the hypervisor to perform the external function call.
	__asm__ volatile(
		"mov $" SYMADDR_STR(lnx_sys_rename) ", %%rbx;" // RBX gets jump target

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
		"m"(oldname_stack_buffer), "m"(newname_stack_buffer),
		"m"(return_value)
		:
		"rax", "rbx", "rdi", "rsi"
	);



	// return to caller
	return return_value;
}
