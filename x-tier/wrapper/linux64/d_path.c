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
 * From the kernel (dcache.c):
 * d_path - return the path of a dentry
 * @path: path to report
 * @buf: buffer to return value in
 * @buflen buffer length
 *
 * We currently only copy the buffer and assume the path 
 * resides in kernel space.
 *
 */
char * d_path(void *path, char *buf, int buflen)
{  	
	// Stores the size of the data that has to be placed on 
	// the kernel stack
	unsigned long esp_offset = 0;
	
	// Stores the return value of the d_path function
	unsigned long d_path_ret = 0;
	
	// Loop counter
	int i, j;

        // COPY arguments
	unsigned long new_buf = 0; // Only have to copy buf in this case
	// Reserve space for buf on kernel stack
	esp_offset += buflen;
	// Change buf pointer to new value
	new_buf = kernel_esp - buflen;

        // CALL is executed
        __asm__ volatile("mov %0, %%rbx;"		// Target Address in RBX
  			 // Set ARGs
			 "mov %3, %%rdi;"		// ARG 1
			 "mov %4, %%rsi;"		// ARG 2
			 "mov $0x0, %%rdx;"
			 "mov %5, %%edx;"		// ARG 3

			 "mov %1, %%rax;"	        // MOV orig kernel_stack into rax
			 "sub %2, %%rax;"               // Decrease the stack pointer by the amount
							// of data that has been added to the kernel stack.
			 "push %%rbp;"			// SAVE EBP
			 "mov %%rsp, %%rbp;"		// SAVE stack pointer
			 "mov %%rax, %%rsp;" 		// Set stack pointer
			 "mov " COMMAND ", %%rax;"	// COMMAND in RAX
                         "int " COMMAND_INTERRUPT ";"   // Send command interrupt
			 "mov %%rbp, %%rsp;"		// Restore RSP
			 "pop %%rbp;"			// Restore RBP
			 // Save Return value
			 "mov %%rax, %6;"
                        :
                        :"r"(target_address), "r"(kernel_esp), 
			 "r"(esp_offset),
			 // ARGS
			 "m"(path), "m"(new_buf), "m"(buflen),
			 // Return value
			 "m"(d_path_ret)
                        :"rax", "rbx", "rdi", "rsi", "rdx"
                        );
	
	// Copy the data back
	for(i = (d_path_ret - new_buf), j = 0; i < buflen; i++, j++)
	{
	  buf[i] = ((char *)d_path_ret)[j];
	}
	
	// Return to caller
        return ((char *)((unsigned long)buf + (d_path_ret - new_buf)));
}
