
#include "../../../tmp/sysmap.h"  // kernel symbol names

#include <stdint.h>
#include <asm/stat.h>

/**
 * generated with: './wrapper_generator.py' '-r' 'int' '-i' '<asm/stat.h>' 'cp_new_stat' 'lnx_cp_new_stat' 'in char[kstat_size] kstat' 'out char[sizeof(struct stat)] stat' 'int kstat_size'
 */

// variables to be patches by injection shellcode, in .text section
unsigned long kernel_esp     __attribute__ ((section (".text"))) = 0;
unsigned long target_address __attribute__ ((section (".text"))) = 0;

int cp_new_stat(char *kstat, char *stat, int kstat_size) {
	unsigned long esp_offset = 0;   // kernel stack allocation size
	int return_value = 0; // function call return value

	int64_t i = 0;


	// === argument: char kstat[kstat_size]

	char *kstat_stack_buffer = (char *)(kernel_esp - (esp_offset + kstat_size));
	for (i = 0; i < (int64_t)kstat_size; i++) {
		kstat_stack_buffer[i] = kstat[i];
	}

	esp_offset += kstat_size;

	char *stat_stack_buffer = (char *)(kernel_esp - (esp_offset + sizeof(struct stat)));
	esp_offset += sizeof(struct stat); // reserve space for stat


	// store the prepared arguments to registers
	// then ask the hypervisor to perform the external function call.
	__asm__ volatile(
		"mov $" SYMADDR_STR(lnx_cp_new_stat) ", %%rbx;" // RBX gets jump target

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
		"m"(kstat_stack_buffer), "m"(stat_stack_buffer), "m"(kstat_size),
		"m"(return_value)
		:
		"rax", "rbx", "rdi", "rsi", "rdx"
	);


	for (i = 0; i < (int64_t)sizeof(struct stat); i++) {
		stat[i] = stat_stack_buffer[i];
	}


	// return to caller
	return return_value;
}
