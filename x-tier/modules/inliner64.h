/*
 * Inline Wrapper that can be used to send specifc commands to the hypervisor.
 */

// The number of the command interrupt e.g. Hypercall
#define COMMAND_INTERRUPT "$42"
#define COMMAND_DATA_TRANSFER "$3"

inline void data_transfer(char *data, long size) {
	__asm__ volatile(
		"mov %0, %%rbx;"                // ARG1: data
		"mov %1, %%rcx;"                // ARG2: size
		"mov " COMMAND_DATA_TRANSFER ", %%rax;" // Data Transfer is 3
		"int " COMMAND_INTERRUPT ";"    // Send command interrupt
		:                               // Output
		:
		"r"(data), "r"(size)            // ARGS
		:
		"rax", "rbx", "rcx");
}
