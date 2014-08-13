/*
 * We currently cannot resolve symbols that are not located
 * in the symbol table e.g. symbols that are not exported
 * as system calls for instance. Thus we used fixed addresses
 * for now.
 */

#include "../../../tmp/sysmap.h"
#include <asm/stat.h>

// The command in the command register - 42 for external function call
#define COMMAND "$42"

// The number of the command interrupt e.g. Hypercall
#define COMMAND_INTERRUPT "$42"

// Data will be patched by the shellcode
// Place this variables into text to get a fixed offset
unsigned long kernel_esp     __attribute__ ((section (".text"))) = 0;
unsigned long target_address __attribute__ ((section (".text"))) = 0;

/*
 * 64-bit Calling Conventions
 *
 * 1st ARG: %RDI
 * 2nd ARG: %RSI
 * 3rd ARG: %RDX
 * 4th ARG: %RCX
 * 5th ARG: %R8
 * 6th ARG: %R9
 * 7th ARG - nth ARG: on stack from right to left
 */

/*
 * From the kernel (fs/stat.c):
 *  - Get information about a file
 * @path: The path to the file.
 * @stat: Stat structure that will contain the results.
 *
 * Notice: This is a "more" platform independetn version of stat, since
 * it uses the kstat struct instead of the stat struct. Latter may be either
 * of type old_stat or type new_stat which will defer in size.
 *
 */
long cp_new_stat(char *kstat, char *stat, int kstat_size)
{
	// Stores the size of the data that has to be placed on
	// the kernel stack
	unsigned long esp_offset = 0;

	// Stores the return value of the cp_new_stat_ret function
	unsigned long cp_new_stat_ret = 0;

	// Loop counter
	int i;

	// COPY arguments
	unsigned long new_kstat = 0;
	unsigned long new_stat = 0;

	// Reserve space for the path and the stat buffer
	esp_offset += kstat_size;
	esp_offset += sizeof(struct stat);
	// Change pointer to new values
	new_kstat = kernel_esp - kstat_size;
	new_stat = kernel_esp - esp_offset;

	// Copy Kstat
	for (i = 0; i < kstat_size; i++) {
		((char *)new_kstat)[i] = kstat[i];
	}

	// CALL is executed
	__asm__ volatile(
		"mov $" SYMADDR_STR(lnx_cp_new_stat) ", %%rbx;" // Target Address in RBX
		                               // Set ARGs
		"mov %2, %%rdi;"               // ARG 1
		"mov %3, %%rsi;"               // ARG 2

		"mov %0, %%rax;"               // MOV orig kernel_stack into rax
		"sub %1, %%rax;"               // Decrease the stack pointer by the amount
		                               // of data that has been added to the kernel stack.
		"push %%rbp;"                  // SAVE EBP
		"mov %%rsp, %%rbp;"            // SAVE stack pointer
		"mov %%rax, %%rsp;"            // Set stack pointer
		"mov " COMMAND ", %%rax;"      // COMMAND in RAX
		"int " COMMAND_INTERRUPT ";"   // Send command interrupt
		"mov %%rbp, %%rsp;"            // Restore RSP
		"pop %%rbp;"                   // Restore RBP

		"mov %%rax, %4;" // Save Return value
		:
		:
		"r"(kernel_esp),
		"r"(esp_offset),
		// ARGS
		"m"(new_kstat), "m"(new_stat),
		// Return value
		"m"(cp_new_stat_ret)
		:
		"rax", "rbx", "rdi", "rsi", "rdx");

	// Copy stat back
	for(i = 0; i < sizeof(struct stat); i++) {
		((char*)stat)[i] = ((char *)new_stat)[i];
	}

	// Return to caller
	return cp_new_stat_ret;
}
