/*
 * X-TIER proudly presents the ArrPreter
 *          inspired by chrschn
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <syscall.h>
#include <string.h>
#include <time.h>
#include <string>
#include <unordered_map>

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "X-TIER.h"
#include "X-TIER/X-TIER_external_command.h"

#include "pin.H"


#include "../../libinject/x-inject.h"

// +---------------------
// |     DEFINES
// +---------------------
// We leave some file descriptors for the system and
// use all numbers above this value
#define FILE_DESCRIPTOR_OFFSET 42
#define MODULE_PREFIX "/tmp/"

// +---------------------
// |     KNOBS
// +---------------------
KNOB<int> KnobMonitorPort(KNOB_MODE_WRITEONCE, "pintool", "monitorPort", "0",
                          "the port the monitor is running on");

// +---------------------
// |     GLOBALS
// +---------------------
unsigned long    entryPoint         = 0;
bool             entryPointPassed   = false;
unsigned int     current_syscall    = 0;
bool             skip_next_syscall  = false;
bool             updateContext      = false;
SYSCALL_STANDARD sysCallStd         = SYSCALL_STANDARD_INVALID;
int64_t          syscall_return_val = 0;

std::unordered_map<int, struct file_state> files;
// We leave some unused handles for STDIN, STDOUT etc.
unsigned int file_handles = FILE_DESCRIPTOR_OFFSET;

void emergency_exit();

int strpcmp(const char *search, const char *prefix) {
	return strncmp(search, prefix, strlen(prefix));
}

void OnOpen(CONTEXT *ctxt, SYSCALL_STANDARD std) {
	char *path  = (char *)PIN_GetSyscallArgument(ctxt, std, 0);
	int   flags = (int)PIN_GetSyscallArgument(ctxt, std, 1);
	int   mode  = (int)PIN_GetSyscallArgument(ctxt, std, 2);

	struct received_data recv_data;

	// Try to open the file within the guest.
	struct injection *injection = new_injection(MODULE_PREFIX "open.inject");

	// Code
	injection_load_code(injection);

	// Args
	add_string_argument(injection, path);
	add_int_argument(injection, flags);
	add_int_argument(injection, mode);

	// Consolidate
	injection = consolidate(injection);

	// Go
	PRINT_DEBUG("Trying to open file '%s' (flags 0x%x, mode 0x%x) within the guest...\n", path, flags, mode);
	inject_module(injection, &recv_data);

	free_injection(injection);

	if (recv_data.return_value >= 0) {
		// File can be opened
		PRINT_DEBUG("Could open file '%s'\n", path);
		file_handles++;

		// Create file descriptor
		struct file_state fd;
		fd.fd       = file_handles;
		fd.path     = path;
		fd.flags    = flags;
		fd.mode     = mode;
		fd.position = 0;
		fd.getdents = 0;

		files[file_handles] = fd;

		// Return our handle
		syscall_return_val = file_handles;
	}
	else {
		PRINT_DEBUG("Could not open file '%s'\n", path);
		syscall_return_val = recv_data.return_value;
	}

	// Skip system call
	skip_next_syscall = true;
}


void OnOpenAt(CONTEXT *ctxt, SYSCALL_STANDARD std) {
	char *path  = (char *)PIN_GetSyscallArgument(ctxt, std, 1);
	int   flags = (int)PIN_GetSyscallArgument(ctxt, std, 2);
	int   mode  = (int)PIN_GetSyscallArgument(ctxt, std, 3);

	struct received_data recv_data;

	// Try to open the file within the guest.
	// Notice that we handle an openAt currently using open.
	struct injection *injection = new_injection(MODULE_PREFIX "open.inject");

	// Code
	injection_load_code(injection);

	// Args
	add_string_argument(injection, path);
	add_int_argument(injection, flags);
	add_int_argument(injection, mode);

	// Consolidate
	injection = consolidate(injection);

	print_injection(injection);

	// Go
	PRINT_DEBUG("Trying to open file '%s' within the guest...\n", path);
	inject_module(injection, &recv_data);

	free_injection(injection);

	if (recv_data.return_value >= 0) {
		// File can be opened
		PRINT_DEBUG("Could open file '%s'\n", path);

		// Create file descriptor
		struct file_state fd;

		file_handles++;
		fd.fd       = file_handles;
		fd.path     = path;
		fd.flags    = flags;
		fd.mode     = mode;
		fd.position = 0;
		fd.getdents = 0;

		files[file_handles] = fd;

		// Return our handle fd id
		syscall_return_val = file_handles;
	}
	else {
		PRINT_DEBUG("Could not open file '%s'\n", path);
		syscall_return_val = -1;
	}

	// Skip system call
	skip_next_syscall = true;
}

void OnGetdents(CONTEXT *ctxt, SYSCALL_STANDARD std) {
	int fd = (int)PIN_GetSyscallArgument(ctxt, std, 0);
	char *dirp = (char *)PIN_GetSyscallArgument(ctxt, std, 1);
	int count = (int)PIN_GetSyscallArgument(ctxt, std, 2);

	struct received_data recv_data;

	struct injection *injection = NULL;
	struct file_state fs;

	if (files.find(fd) == files.end()) {
		PRINT_ERROR("File Descriptor %d unkown!\n", fd);
		return;
	}

	fs = files[fd];

	// We only inject on the first getdents call
	if (!fs.getdents) {
		// Setup Injection
		injection = new_injection(MODULE_PREFIX "getdents.inject");

		// Code
		injection_load_code(injection);

		// Args
		add_string_argument(injection, fs.path.c_str());

		// Consolidate
		injection = consolidate(injection);

		// Go
		PRINT_DEBUG("Trying to get directory contents of '%s'...\n",
		            fs.path.c_str());
		inject_module(injection, &recv_data);

		free_injection(injection);

		if (count > recv_data.length) {
			// Dirp is larger than the data we received
			memcpy(dirp, recv_data.data, recv_data.length);
			fs.getdents = recv_data.length;
			syscall_return_val = recv_data.return_value;
		}
		else {
			PRINT_WARNING("Data returned is larger than the size of the buffer!\n");
			memcpy(dirp, recv_data.data, count);
			fs.getdents = count;
			syscall_return_val = count;
		}
	}
	// This currenlty does not work, since system calls that are between two getdents calls
	// will change the data!
	/*
	else {
		// This is not the first call to getdents on that file
		if (fs.getdents == data_current_len)
		{
			// We already gave all the data we have
			syscall_return_val = 0;
			fs.getdents = 0;
		}
		else
		{
			if (fs.getdents + count < data_current_len)
			{
				PRINT_WARNING("Data returned is larger than the size of the buffer!\n");
				memcpy(dirp, data + fs.getdents, count);
				fs.getdents += count;
				syscall_return_val = count;
			}
			else
			{
				memcpy(dirp, data + fs.getdents, data_current_len);
				syscall_return_val = data_current_len - fs.getdents;
				fs.getdents = data_current_len;
			}
		}
	}
	*/
	else {
		syscall_return_val = 0;
		fs.getdents = 0;
	}

	// Insert update object
	files[fs.fd] = fs;

	// Skip system call
	skip_next_syscall = true;
}


void OnRead(CONTEXT *ctxt, SYSCALL_STANDARD std) {
	int fd = (int)PIN_GetSyscallArgument(ctxt, std, 0);
	char *buf = (char *)PIN_GetSyscallArgument(ctxt, std, 1);
	int buf_size = (int)PIN_GetSyscallArgument(ctxt, std, 2);

	struct received_data recv_data;

	struct injection *injection = NULL;
	struct file_state fs;

	// take the corresponding file_state from our stored file state dict
	if (files.find(fd) == files.end()) {
		PRINT_ERROR("File Descriptor %d unkown!\n", fd);
		return;
	}

	fs = files[fd];

	if (fs.position != 0) {
		PRINT_WARNING("starting to read at position %d\n", fs.position);
	}

	// Setup Injection
	injection = new_injection(MODULE_PREFIX "read.inject");

	// Code
	injection_load_code(injection);

	// Args
	add_string_argument(injection, fs.path.c_str());
	add_int_argument(injection, fs.flags);
	add_int_argument(injection, fs.position);
	add_int_argument(injection, buf_size);

	// Consolidate
	injection = consolidate(injection);

	// Go
	PRINT_DEBUG("Trying to read %d bytes from file '%s'...\n", buf_size, fs.path.c_str());

	inject_module(injection, &recv_data);

	if (recv_data.return_value >= buf_size) {
		PRINT_WARNING("!\n!\n!\n READ MORE DATA THAN REQUESTED \n!\n!\n!\n");
		emergency_exit();
	}
	else if (recv_data.return_value >= 0) {
		memcpy(buf, recv_data.data, recv_data.return_value);
		fs.position        += recv_data.return_value;
		syscall_return_val  = recv_data.return_value;
	}


	// Clean up
	free_injection(injection);

	// Insert updated object
	files[fs.fd] = fs;

	// Skip system call
	skip_next_syscall = true;
}


void OnStat(CONTEXT *ctxt, SYSCALL_STANDARD std) {

	struct received_data recv_data;

	// Setup Injection
	struct injection *injection = new_injection(MODULE_PREFIX "stat.inject");

	// Code
	injection_load_code(injection);

	// Args
	add_string_argument(injection, (char *)PIN_GetSyscallArgument(ctxt, std, 0));

	// Consolidate
	injection = consolidate(injection);

	// Go
	PRINT_DEBUG("Trying to stat file '%s'...\n", (char *)PIN_GetSyscallArgument(ctxt, std, 0));
	inject_module(injection, &recv_data);

	// Copy stat data
	memcpy((char *)PIN_GetSyscallArgument(ctxt, std, 1), recv_data.data, recv_data.length);

	// Skip system call
	skip_next_syscall = true;

	// Clean up
	free_injection(injection);
}


/**
 * seek syscall.
 * currently, we assume the seek is successful.
 * this may be checked by another injection in the future.
 */
void OnSeek(CONTEXT *ctxt, SYSCALL_STANDARD std) {
	int  fd       = (int)PIN_GetSyscallArgument(ctxt, std, 0);
	long position = (long)PIN_GetSyscallArgument(ctxt, std, 1);
	int  whence   = (int)PIN_GetSyscallArgument(ctxt, std, 2);

	struct file_state fs;

	if (files.find(fd) == files.end()) {
		PRINT_ERROR("File Descriptor %d unkown!\n", fd);
		return;
	}

	fs = files[fd];

	switch (whence) {
	case SEEK_SET:
		fs.position         = position;
		syscall_return_val  = position;
		skip_next_syscall   = true;
		break;
	case SEEK_CUR:
		fs.position        += position;
		syscall_return_val  = fs.position;
		skip_next_syscall   = true;
		break;
	}

	// Insert updated object
	files[fs.fd] = fs;
}


void OnClose(CONTEXT *ctxt, SYSCALL_STANDARD std) {
	// Get fd
	int fd = (int)PIN_GetSyscallArgument(ctxt, std, 0);

	// Remove from hash
	files.erase(fd);

	// Set return value and skip call
	syscall_return_val = 0;
	skip_next_syscall  = true;
}


void OnImageLoad(IMG img, void *v) {
	// Obtain the entry point of the main program
	if (IMG_IsMainExecutable(img)) {
		entryPoint = IMG_Entry(img);

		PRINT_DEBUG_FULL("Entry Point of traced executable is @ 0x%lx\n", entryPoint);
	}
}


void OnSysCall(CONTEXT *ctxt) {
	current_syscall = 0;
	SYSCALL_STANDARD std = sysCallStd;
	char *path = NULL;
	int fd = -1;

	if (entryPointPassed) {
		current_syscall = PIN_GetSyscallNumber(ctxt, std);

		PRINT_DEBUG("====================================================\n");
		PRINT_DEBUG("catched syscall %d\n", current_syscall);

		// Filter
		switch (current_syscall) {
		case __NR_open:
		case __NR_stat:
		case __NR_lstat:
			path = (char *) PIN_GetSyscallArgument(ctxt, std, 0);
			break;
		case __NR_openat:
			path = (char *) PIN_GetSyscallArgument(ctxt, std, 1);
			break;
		case __NR_write:
		case __NR_read:
		case __NR_close:
		case __NR_fstat:
		case __NR_lseek:
			fd = (int) PIN_GetSyscallArgument(ctxt, std, 0);
			break;
		}

		if (path) {
			// Check if the host should handle this one
			// Ignore the following paths
			if (strpcmp(path, "/usr/lib") == 0 ||
			    strpcmp(path, "/lib") == 0 ||
			    strstr(path, "locale") != NULL ||
			    strpcmp(path, "/proc/self/") == 0 ||
			    strpcmp(path, "/dev/tty") == 0) {
				PRINT_DEBUG("path filter matched, running syscall %d on host.\n", current_syscall);
				return;
			}
		}

		if (fd >= 0) {
			// Ignore fd 0-2
			if (fd < FILE_DESCRIPTOR_OFFSET) {
				PRINT_DEBUG("fd filter matched, running syscall %d on host.\n", current_syscall);
				return;
			}
		}

		// Process System call
		switch (current_syscall) {
		case __NR_getdents:
			PRINT_DEBUG("This is a getdents system call. Its buffer is located @ 0x%lx.\n",
			            PIN_GetSyscallArgument(ctxt, std, 1));
			OnGetdents(ctxt, std);
			break;
		case __NR_open:
			PRINT_DEBUG("This is an open system call which tries to open directory '%s'.\n",
			            (char *)PIN_GetSyscallArgument(ctxt, std, 0));
			OnOpen(ctxt, std);
			break;
		case __NR_openat:
			PRINT_DEBUG("This is an openAt system call which tries to open directory '%s'.\n",
			            (char *)PIN_GetSyscallArgument(ctxt, std, 1));
			OnOpenAt(ctxt, std);
			break;
		case __NR_close:
			PRINT_DEBUG("This is an close system call which tries to close fd '%d'.\n",
			            (int)PIN_GetSyscallArgument(ctxt, std, 0));
			OnClose(ctxt, std);
			break;
		case __NR_fstat:
			PRINT_DEBUG("This is an fstat system call on fd '%d'.\n",
			            (int)PIN_GetSyscallArgument(ctxt, std, 0));
			//OnStat(ctxt, std);
			break;
		case __NR_stat:
			PRINT_DEBUG("This is an stat system call on path '%s'.\n",
			            (char *)PIN_GetSyscallArgument(ctxt, std, 0));
			OnStat(ctxt, std);
			break;
		case __NR_lstat:
			PRINT_DEBUG("This is an lstat system call on path '%s'.\n",
			            (char *)PIN_GetSyscallArgument(ctxt, std, 0));
			break;
		case __NR_read:
			PRINT_DEBUG("This is an read system call on fd %d.\n",
			            (int)PIN_GetSyscallArgument(ctxt, std, 0));
			OnRead(ctxt, std);
			break;
		case __NR_write:
			PRINT_DEBUG("This is an write system call on fd %d.\n",
			            (int)PIN_GetSyscallArgument(ctxt, std, 0));
			break;
		case __NR_lseek:
			PRINT_DEBUG("This is an lseek system call on fd %d.\n",
			            (int)PIN_GetSyscallArgument(ctxt, std, 0));
			OnSeek(ctxt, std);
			break;
		}
	}

	if (skip_next_syscall) {
		// Set next instruction
		ADDRINT next_instruction  = PIN_GetContextReg(ctxt, REG_INST_PTR);
		next_instruction         += 2;

		PRINT_DEBUG("Skipping system call %d!\n", current_syscall);
		PRINT_DEBUG_FULL("Setting EIP to 0x%lx\n", next_instruction);
		PRINT_DEBUG_FULL("Setting return value to %ld\n", syscall_return_val);

		// Reset
		skip_next_syscall = false;

		// Update context
		PIN_SetContextReg(ctxt, REG_GAX, syscall_return_val);
		PIN_SetContextReg(ctxt, REG_INST_PTR, next_instruction);

		PIN_ExecuteAt(ctxt);
	}
	else {
		PRINT_DEBUG("System call will be executed...\n");
	}
}

void OnSysExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
	if (entryPointPassed) {
		PRINT_DEBUG("Syscall %d returned with status %ld\n", current_syscall,
		            PIN_GetSyscallReturn(ctxt, std));
		PRINT_DEBUG("====================================================\n");
	}
}

void OnInstruction(INS ins, void *v) {
	if (!entryPointPassed && INS_Address(ins) == entryPoint) {
		entryPointPassed = true;

		PRINT_DEBUG_FULL("Reached entry point of main exectuable\n");
	}

	if (entryPointPassed) {
		if (INS_IsSyscall(ins)) {
			// Set Syscall std
			sysCallStd = INS_SyscallStd(ins);

			// Call system call handler
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(OnSysCall),
			               IARG_CONTEXT, IARG_END);
		}
	}
}


void Fini(INT32 code, VOID *v) {
	terminate_connection();
}

void emergency_exit() {
	terminate_connection();
	exit(1);
}


int main(int argc, char *argv[]) {
	// Init PIN
	PIN_Init(argc, argv);

	// Get Monitor fd
	init_connection(KnobMonitorPort.Value());

	// Intercept image load
	IMG_AddInstrumentFunction(OnImageLoad, 0);

	// Intercept instruction execution
	INS_AddInstrumentFunction(OnInstruction, 0);

	// Intercept system calls
	//PIN_AddSyscallEntryFunction(OnSysEnter, 0);
	PIN_AddSyscallExitFunction(OnSysExit, 0);

	// Cleanup
	PIN_AddFiniFunction(Fini, 0);

	// Go
	PIN_StartProgram();

	return 0;
}
