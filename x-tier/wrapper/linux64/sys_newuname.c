
#include "../../../tmp/sysmap.h"  // kernel symbol names

#include <stdint.h>
#include <sys/utsname.h>

/**
 * generated with: './wrapper_generator.py' '-i' '<sys/utsname.h>' 'sys_newuname' 'lnx_sys_newuname' 'out struct utsname*[sizeof(struct utsname)] unamebuf'
 */

// variables to be patches by injection shellcode, in .text section
unsigned long kernel_esp     __attribute__ ((section (".text"))) = 0;
unsigned long target_address __attribute__ ((section (".text"))) = 0;

int64_t sys_newuname(char *unamebuf) {
	unsigned long esp_offset = 0;   // kernel stack allocation size
	int64_t return_value = 0; // function call return value

	int64_t i = 0;


	char *unamebuf_stack_buffer = (char *)(kernel_esp - (esp_offset + sizeof(struct utsname)));
	esp_offset += sizeof(struct utsname); // reserve space for unamebuf


	// store the prepared arguments to registers
	// then ask the hypervisor to perform the external function call.
	__asm__ volatile(
		"mov $" SYMADDR_STR(lnx_sys_newuname) ", %%rbx;" // RBX gets jump target

		"mov $0, %%rdi;"  // zero arg 0
		"mov %2, %%rdi;"  // prepare arg 0

		"mov  %0, %%rax;"      // store original kernel_stack into rax
		"sub  %1, %%rax;"      // decrease stack ptr by allocation amount
		"push %%rbp;"          // save EBP
		"mov  %%rsp, %%rbp;"   // save stack pointer
		"mov  %%rax, %%rsp;"   // set stack pointer
		"mov  $42, %%rax;"     // select `command` as interrupt handler in RAX
		"int  $42;"            // send interrupt, hypercall happens here
		"mov  %%rbp, %%rsp;"   // restore RSP
		"pop  %%rbp;"          // restore RBP

		"mov  %%rax, %3;"      // save return value
		:
		:
		"r"(kernel_esp),
		"r"(esp_offset),
		"m"(unamebuf_stack_buffer),
		"m"(return_value)
		:
		"rax", "rbx", "rdi"
	);


	for (i = 0; i < (int64_t)sizeof(struct utsname); i++) {
		unamebuf[i] = unamebuf_stack_buffer[i];
	}


	// return to caller
	return return_value;
}
