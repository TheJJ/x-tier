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
 * sys_read - Read from the given file pointer
 * @fd: The file pointer to read from
 * @buf: The buffer to read to
 * @buf_size: The size of the buffer
 *
 */
long sys_read(unsigned int fd, char *buf, long buf_size) {
	// Stores the size of the data that has to be placed on
	// the kernel stack
	unsigned long esp_offset = 0;

	// Stores the return value of the sys_read function
	long read_ret = 0;

	// Loop counter
	int i;

	// COPY arguments
	unsigned long new_buf = 0;
	// Reserve space for the new buffer on kernel stack
	esp_offset += buf_size;
	// Change buf pointer to new value
	new_buf = kernel_esp - buf_size;

	// CALL is executed
	__asm__ volatile(
		"mov $" SYMADDR_STR(lnx_sys_read) ", %%rbx;" // Target Address in RBX
		// Set ARGs
		"mov $0x0, %%rdi;"              // Clear RDI, since we only write to edi
		"mov %2, %%edi;"                // ARG 1
		"mov %3, %%rsi;"                // ARG 2
		"mov %4, %%rdx;"                // ARG 3

		"mov %0, %%rax;"                // MOV orig kernel_stack into rax
		"sub %1, %%rax;"                // Decrease the stack pointer by the amount
		                                // of data that has been added to the kernel stack.
		"push %%rbp;"                   // SAVE EBP
		"mov %%rsp, %%rbp;"             // SAVE stack pointer
		"mov %%rax, %%rsp;"             // Set stack pointer
		"mov " COMMAND ", %%rax;"       // COMMAND in RAX
		"int " COMMAND_INTERRUPT ";"    // Send command interrupt
		"mov %%rbp, %%rsp;"             // Restore RSP
		"pop %%rbp;"                    // Restore RBP
		                                // Save Return value
		"mov %%rax, %5;"
		:
		:
		"r"(kernel_esp),
		"r"(esp_offset),
		"m"(fd), "m"(new_buf), "m"(buf_size), // args
		"m"(read_ret)                   // Return value
		:
		"rax", "rbx", "rdi", "rsi", "rdx");

	// Copy the data back
	for(i = 0; i < read_ret; i++) {
		((char *)buf)[i] = ((char *)new_buf)[i];
	}

	// Return to caller
	return read_ret;
}
