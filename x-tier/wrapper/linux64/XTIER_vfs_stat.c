/*
 * We currently cannot resolve symbols that are not located
 * in the symbol table e.g. symbols that are not exported
 * as system calls for instance. Thus we used fixed addresses
 * for now.
 */

#include "../../../tmp/sysmap.h"

// The command in the command register - 42 for external function call
#define COMMAND "$42"

// The number of the command interrupt e.g. Hypercall
#define COMMAND_INTERRUPT "$42"

// Data will be patched by the shellcode
// Place this variables into text to get a fixed offset
unsigned long kernel_esp     __attribute__ ((section (".text"))) = 0xdeadbeefbeefdead;
unsigned long target_address __attribute__ ((section (".text"))) = 0xaaaadeadbeefbbbb;

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
 * vfs_stat - Get information about a file
 * @path: The path to the file.
 * @stat: Stat structure that will contain the results.
 * @stat_size: The siue of the stat struct
 *
 * Notice: This is a "more" platform independent version of stat, since
 * it uses the kstat struct instead of the stat struct. Latter may be either
 * of type old_stat or type new_stat which will defer in size.
 *
 */
long XTIER_vfs_stat(char *path, char *stat, int stat_size)
{
	// Stores the size of the data that has to be placed on
	// the kernel stack
	unsigned long esp_offset = 0;

	// Stores the return value of the vfs_stat function
	unsigned long stat_ret = 0;

	// Loop counter
	int i;

	// Helper
	char *tmp = path;

	// COPY arguments
	char *new_path = 0;
	unsigned int path_len = 0;
	unsigned long new_stat = 0;

	// Length of the filename?
	while ((*tmp) != '\0') {
		path_len++;
		tmp++;
	}

	// Increase count to account for the NULL-byte
	path_len++;

	// Reserve space for the path and the stat buffer
	esp_offset += path_len;
	esp_offset += stat_size;
	// Change pointer to new values
	new_path = (char *)(kernel_esp - path_len);
	new_stat = kernel_esp - esp_offset;

	// Copy path
	for (i = 0; i < path_len; i++) {
		new_path[i] = path[i];
	}

	// CALL is executed
	__asm__ volatile(
		"mov $" str_lnx_vfs_stat ", %%rbx;" // Target Address in RBX
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

		"mov %%rax, %4;"               // Save Return value
		:
		:
		"r"(kernel_esp),
		"r"(esp_offset),
		// ARGS
		"m"(new_path), "m"(new_stat),
		// Return value
		"m"(stat_ret)
		:
		"rax", "rbx", "rdi", "rsi", "rdx");

	// Copy the data back
	for (i = 0; i < stat_size; i++) {
		((char*)stat)[i] = ((char *)new_stat)[i];
	}

	// Return to caller
	return stat_ret;
}
