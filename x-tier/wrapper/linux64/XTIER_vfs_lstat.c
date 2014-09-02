
#include "../../../tmp/sysmap.h"  // kernel symbol names
#include <stdint.h>

/**
 * generated with: './wrapper_generator.py' '-r' 'int' 'XTIER_vfs_lstat' 'lnx_vfs_lstat' 'in char *path' 'out char[kstat_size] kstat' 'int kstat_size'
 */

// variables to be patches by injection shellcode, in .text section
unsigned long kernel_esp     __attribute__ ((section (".text"))) = 0;
unsigned long target_address __attribute__ ((section (".text"))) = 0;

int XTIER_vfs_lstat(char *path, char *kstat, int64_t kstat_size) {
	unsigned long esp_offset = 0;   // kernel stack allocation size
	int return_value = 0; // function call return value

	int i = 0;


	// === argument: char *path
	int path_length = 1; // including \0
	char *path_len_tmp = (char *)path;

	while ((*path_len_tmp) != '\0') {
		path_length  += 1;
		path_len_tmp += 1;
	}

	
	char *path_stack_buffer = (char *)(((char *)kernel_esp) - (esp_offset + path_length));
	for (i = 0; i < path_length; i++) {
		path_stack_buffer[i] = path[i];
	}

	esp_offset += path_length;
	// ====

	char *kstat_stack_buffer = (char *)(((char *)kernel_esp) - (esp_offset + kstat_size));
	esp_offset += kstat_size; // reserve space for kstat
            

	// store the prepared arguments to registers
	// then ask the hypervisor to perform the external function call.
	__asm__ volatile(
		"mov $" SYMADDR_STR(lnx_vfs_lstat) ", %%rbx;" // RBX gets jump target

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
		"m"(path_stack_buffer), "m"(kstat_stack_buffer), "m"(kstat_size),
		"m"(return_value)
		:
		"rax", "rbx", "rdi", "rsi", "rdx"
	);


	for (i = 0; i < kstat_size; i++) {
		kstat[i] = kstat_stack_buffer[i];
	}


	// return to caller
	return return_value;
}

