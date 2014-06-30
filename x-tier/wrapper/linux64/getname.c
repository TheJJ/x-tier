// The command in the command register - 42 for external function call
#define COMMAND "$42"

// The number of the command interrupt e.g. Hypercall
#define COMMAND_INTERRUPT "$42"

// Data will be patched by the shellcode
// Place this variables into text to get a fixed offset
unsigned long kernel_esp __attribute__ ((section (".text"))) = 0;
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
 * (namei.c):
 * getname - Lookup the name of a file based on a user-provided
 * filename.
 *
 * @filename: A userspace pointer to the filename.
 *
 */
char *getname(const char *filename) {
	// Stores the size of the data that has to be placed on
	// the kernel stack
	unsigned long esp_offset = 0;

	// Stores the return value of the d_path function
	char *getname_ret = 0;

	// Get the current stack
	unsigned long current_esp = 0;
	__asm__ volatile(
		"mov %%rsp, %0;"
		: "=m"(current_esp)
		:
		:);

	// Check if we are using the kernel stack or our own stack
	if (kernel_esp - current_esp < 8192) {
		// We are on the kernel stack => do not modify esp
		// CALL is executed
		__asm__ volatile(
			"mov %0, %%rbx;"              // Target Address in RBX
			                              // Set ARGs
			"mov %1, %%rdi;"              // ARG 1
			"mov " COMMAND ", %%rax;"     // COMMAND in RAX
			"int " COMMAND_INTERRUPT ";"  // Send command interrupt
			"mov %%rax, %2;"              // Save Return value
			:
			:
			"r"(target_address),
			// ARGS
			"m"(filename),
			// Return value
			"m"(getname_ret)
			:
			"rax", "rbx", "rdi");
	}
	else {
		// We are on our private stack => stacks need to be switched
		// CALL is executed
		__asm__ volatile(
			"mov %0, %%rbx;"        // Target Address in RBX
			// Set ARGs
			"mov %3, %%rdi;"        // ARG 1
			"mov %1, %%rax;"        // MOV orig kernel_stack into rax
			"sub %2, %%rax;"        // Decrease the stack pointer by the amount
			                        // of data that has been added to the kernel stack.
			"push %%rbp;"           // SAVE EBP
			"mov %%rsp, %%rbp;"         // SAVE stack pointer
			"mov %%rax, %%rsp;"         // Set stack pointer
			"mov " COMMAND ", %%rax;"   // COMMAND in RAX
			"int " COMMAND_INTERRUPT ";"   // Send command interrupt
			"mov %%rbp, %%rsp;"         // Restore RSP
			"pop %%rbp;"            // Restore RBP
			// Save Return value
			"mov %%rax, %4;"
			:
			:
			"r"(target_address), "r"(kernel_esp), "r"(esp_offset),
			// ARGS
			"m"(filename),
			// Return value
			"m"(getname_ret)
			:
			"rax", "rbx", "rdi", "rsi", "rdx");
	}

	// Return to caller
	return getname_ret;
}
