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

// Change the name and add the arguments of the external function.
void wrapper(void) {
	// Stores the size of the data that has to be placed on
	// the kernel stack
	unsigned long esp_offset = 0;

	// COPY arguments

	// CALL is executed
	__asm__ volatile(
		"mov %0, %%rbx;"             // Target Address in RBX
		                             // Set ARGs here
		"mov %1, %%rax;"             // MOV orig kernel_stack into rax
		"sub %2, %%rax;"             // Decrease the stack pointer by the amount of data that has been added to the kernel stack.
		"push %%rbp;"                // SAVE EBP
		"mov %%rsp, %%rbp;"          // SAVE stack pointer
		"mov %%rax, %%rsp;"          // Set stack pointer
		"mov " COMMAND ", %%rax;"    // COMMAND in RAX
		"int " COMMAND_INTERRUPT ";" // Send command interrupt
		"mov %%rbp, %%rsp;"          // Restore RSP
		"pop %%rbp;"                 // Restore RBP
		                             // Save Return value
		                             // "mov %%rax, <ARG>;"
		:
		//output
		:
		"r" (target_address),
		"r" (kernel_esp)
		:
		"rax",
		"rbx");

	// Return to caller
	return;
}
