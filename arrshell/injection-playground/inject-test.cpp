#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <syscall.h>
#include <string.h>
#include <time.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <QHash>
#include <QString>
#include <QTime>

#include "X-TIER.h"
#include "X-TIER/X-TIER_external_command.h"

#define ARR_DEBUG_FULL 6
#define ARR_DEBUG 5
#define ARR_INFO 4
#define ARR_WARNING 3
#define ARR_ERROR 2
#define ARR_CRITICAL 1

#define DEBUG_LEVEL 6

#define msg_print(level, level_string, fmt, ...) \
	do { if (DEBUG_LEVEL >= level) printf("[ arrpreter - %s ] %d : %s(): " fmt, \
	                                      level_string, __LINE__, __func__, ##__VA_ARGS__); } while (0)

#define PRINT_DEBUG_FULL(fmt, ...) msg_print(ARR_DEBUG_FULL, "DEBUG FULL", fmt, ##__VA_ARGS__)
#define PRINT_DEBUG(fmt, ...) msg_print(ARR_DEBUG, "DEBUG", fmt, ##__VA_ARGS__)
#define PRINT_INFO(fmt, ...) msg_print(ARR_INFO, "INFO", fmt, ##__VA_ARGS__)
#define PRINT_WARNING(fmt, ...) msg_print(ARR_WARNING, "WARNING", fmt, ##__VA_ARGS__)
#define PRINT_ERROR(fmt, ...) msg_print(ARR_ERROR, "ERROR", fmt, ##__VA_ARGS__)


unsigned long entryPoint        = 0;
bool          entryPointPassed  = false;
unsigned int  currentSystemCall = 0;
long          returnValue       = 0;


int         monitorPort                = 0;
int         monitorSocket              = 0;
const char *injectionOutputPipePath    = "/tmp/pipe_x-tier_to_ext";
int         injectionOutputFd          = 0;
int         injectionInputFd           = 0;
bool        createdInjectionOutputPipe = false;

char *data = NULL;
unsigned long data_size = 0;
unsigned long data_current_len = 0;


QTime timer;
long  tmpTime, tmpInjectionTime, tmpReceiveTime;
long  totalExecutionTime     = 0;
long  totalInjectionTime     = 0;
long  totalCommunicationTime = 0;
long  totalReceiveTime       = 0;
long  injectionCount         = 0;



bool CreateInjectionOutputPipe(void) {
	int ret = 0;

	// Create named pipe - User Read, Write, Exec
	if (!createdInjectionOutputPipe && (ret = mkfifo(injectionOutputPipePath, S_IRWXU)) != 0) {
		if (errno != EEXIST) {
			PRINT_ERROR("Could not create named pipe '%s' (ret: %d, errno: %d)!\n",
			            injectionOutputPipePath, ret, errno);
			return false;
		}
	}

	createdInjectionOutputPipe = true;
	return true;
}

bool OpenInjectionOutputPipe(void) {
	// Open the fd
	if ((injectionOutputFd = open(injectionOutputPipePath, O_RDONLY)) < 0) {
		PRINT_ERROR("Could not open fd to named pipe '%s' (ret: %d, errno: %d)!\n",
		            injectionOutputPipePath, injectionOutputFd, errno);
		return false;
	}

	return true;
}

bool OpenMonitorConnection(void) {
	struct sockaddr_in server;

	// Create socket
	if ((monitorSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		PRINT_ERROR("Could not create socket!\n");
		return false;
	}

	// Configure
	server.sin_family      = AF_INET;
	server.sin_port        = htons(monitorPort);
	server.sin_addr.s_addr = inet_addr("127.0.0.1");

	// Connect
	if (connect(monitorSocket, (struct sockaddr *)(&server), sizeof(server)) < 0) {
		PRINT_ERROR("Could not connect to server at port %d!\n", monitorPort);
		return false;
	}
	else {
		PRINT_INFO("connected to qemu monitor at port %d!\n", monitorPort);
		return true;
	}
}

bool SendMonitorCommand(const char *command) {
	if (!monitorSocket && !OpenMonitorConnection()) {
		PRINT_ERROR("Could not connect to QEMU Monitor!\n");
		return false;
	}

	// Send command
	if (send(monitorSocket, command, strlen(command), 0) != (int)strlen(command)) {
		PRINT_ERROR("An error occurred while transmitting the '%s' command!\n", command);
		return false;
	}

	return true;
}

void ReceiveDataHelper(void) {
	char *tmp = NULL;
	long ret = 0;

	// Is the data buffer set up?
	if (!data) {
		data_size = 4096;
		data_current_len = 0;
		data = (char *)malloc(data_size);

		// Check allocation
		if (!data) {
			PRINT_ERROR("Could not allocated memory!\n");
			data_size = 0;
			return;
		}
	}

	// Do we have to extend the data buffer?
	//TODO: use realloc
	if (data_current_len == data_size) {
		tmp = (char *)malloc(data_size * 2);

		if (!tmp) {
			PRINT_ERROR("Could not allocated memory!\n");
			return;
		}

		memcpy(tmp, data, data_size);
		free(data);

		// Update
		data = tmp;
		data_size = data_size * 2;
	}

	// Read data
	ret = read(injectionOutputFd, (data + data_current_len), (data_size - data_current_len));

	if (ret < 0) {
		PRINT_ERROR("An error (%ld) occurred while receiving the data!\n", ret);
		return;
	}
	else {
		data_current_len += ret;
	}
}

void ReceiveData(void) {
	// len without \0
	const unsigned int data_begin_len = sizeof(XTIER_EXTERNAL_OUTPUT_BEGIN) - 1;
	const unsigned int data_end_len   = sizeof(XTIER_EXTERNAL_OUTPUT_END) - 1;
	char               data_begin[sizeof(XTIER_EXTERNAL_OUTPUT_BEGIN)];
	long               ret            = 0;
	data_current_len                  = 0;

	// First receive the output begin delimiter
	while ((ret = read(injectionOutputFd, data_begin, data_begin_len)) == 0) {}

	// Begin Time measurement
	tmpReceiveTime = timer.elapsed();

	if ((unsigned int)ret != data_begin_len) {
		PRINT_ERROR("An error occurred while receiving the data begin marker! "
		            "Received %ld bytes instead of %d (errno: %d)\n",
		            ret, data_begin_len, errno);
		return;
	}

	if (strncmp(data_begin, XTIER_EXTERNAL_OUTPUT_BEGIN, data_begin_len) != 0) {
		PRINT_ERROR("Received string (%s) does not match begin marker!\n", data_begin);
		return;
	}

	PRINT_DEBUG_FULL("Received begin marker!\n");


	// Receive data till we get the output delimiter
	PRINT_DEBUG_FULL("Beginning to receive data...\n");
	do {
		PRINT_DEBUG_FULL("Receiving data...\n");
		ReceiveDataHelper();
	}
	while(data_current_len < data_end_len ||
	      strncmp(data + (data_current_len - data_end_len), XTIER_EXTERNAL_OUTPUT_END, data_end_len));

	// Update length
	data_current_len = data_current_len - data_end_len;

	// Receive return value
	returnValue = XTIER_external_command_extract_return_value(data, data_current_len);
	data_current_len -= XTIER_EXTERNAL_COMMAND_RETURN_VALUE_SIZE;
	PRINT_DEBUG("Received return value %ld!\n", returnValue);

	// Notice that we currently _NOT_ remove the end marker and the return value from the
	// received data. May be in the future.
	PRINT_DEBUG_FULL("Received end marker!\n");
	PRINT_DEBUG("Data tansfer of %ld bytes complete...\n", data_current_len);

	// Time Measurement
	totalReceiveTime += (timer.elapsed() - tmpReceiveTime);
}

bool InjectModule(struct injection *injection) {
	struct XTIER_external_command cmd;
	struct XTIER_external_command_redirect re;

	if (!injection) {
		PRINT_ERROR("Injection structure is NULL!\n");
		return false;
	}

	if (!injection->code) {
		PRINT_ERROR("Injection has no code!\n");
		return false;
	}


	// Time measurement of the communcation
	injectionCount++;
	tmpTime = timer.elapsed();

	if (injection->type != CONSOLIDATED) {
		PRINT_ERROR("Injection structure is not consolidated (type: %d)!\n", injection->type);
		return false;
	}

	// Create output pipe if necessary
	PRINT_DEBUG_FULL("Creating Output pipe...\n");
	if (!CreateInjectionOutputPipe()) {
		PRINT_ERROR("Could not create output pipe!\n");
		return false;
	}

	// Prepare for external input
	PRINT_DEBUG_FULL("Sending Commands...\n");
	if (!SendMonitorCommand("x-tier\nexternal\n")) {
		return false;
	}

	// Open input pipe
	PRINT_DEBUG_FULL("Opening Input Pipe...\n");

	struct timespec input_pipe_delay {0, 100000000}; //0.1 s

	//TODO: race condition! wait for qemu to create the file!
	nanosleep(&input_pipe_delay, NULL);

	if (!injectionInputFd) {
		injectionInputFd = open(XTIER_EXTERNAL_COMMAND_PIPE, O_WRONLY);
	}

	if (injectionInputFd < 0) {
		PRINT_ERROR("Could not open fd to cmd input named pipe '%s'!\n", XTIER_EXTERNAL_COMMAND_PIPE);
		return false;
	}

	// Prepare cmd
	cmd.type = INJECTION;
	cmd.data_len = injection_size(injection);
	cmd.redirect = PIPE;

	// Prepare redirect
	re.type = PIPE;
	strcpy(re.filename, injectionOutputPipePath);

	// Write cmd
	PRINT_DEBUG_FULL("Sending external command struct...\n");
	if (write(injectionInputFd, &cmd, sizeof(struct XTIER_external_command)) != sizeof(struct XTIER_external_command)) {
		PRINT_ERROR("An error occurred while writing the command struct. Aborting...\n");
		close(injectionInputFd);
		injectionInputFd = 0;
		return false;
	}

	// Write redirect
	PRINT_DEBUG_FULL("Sending external commmand redirect struct...\n");
	if (write(injectionInputFd, &re, sizeof(struct XTIER_external_command_redirect)) != sizeof(struct XTIER_external_command_redirect)) {
		PRINT_ERROR("An error occurred while writing the redirect struct. Aborting...\n");
		close(injectionInputFd);
		injectionInputFd = 0;
		return false;
	}

	// Write injection
	PRINT_DEBUG_FULL("Sending injection...\n");
	injection_to_fd(injection, injectionInputFd);

	// run the injection!
	SendMonitorCommand("cont\n");

	// Time Measurement of the injection itself
	tmpInjectionTime = timer.elapsed();

	// Open output pipe
	if (injectionOutputFd == 0) {
		if (!OpenInjectionOutputPipe()) {
			PRINT_ERROR("An error occurred while opening the output pipe. Aborting...\n");
			return false;
		}
	}

	// Receive Data
	ReceiveData();

	// Time Measurement of the injection itself
	totalInjectionTime += (timer.elapsed() - tmpInjectionTime);

	// exit x-tier mode and resume vm
	SendMonitorCommand("cont\n");

	// Close connections
	// close(injectionOutputFd);
	// injectionOutputFd = 0;

	// Close inFd
	//close(inFd);

	// Time measurement of the entire communication
	totalCommunicationTime += (timer.elapsed() - tmpTime);
	return true;
}


int main() {
	timer.start();
	monitorPort = 8998;

	struct injection *injection = new_injection("/tmp/lsmod.inject");
	injection_load_code(injection);
	injection = consolidate(injection);
	InjectModule(injection);

	void *result_data = malloc(data_current_len);

	memcpy(result_data, data, data_current_len);

	free_injection(injection);


	// Close Monitor Connection
	if (monitorSocket)
		close(monitorSocket);

	if (injectionOutputFd) {
		// Close Pipe
		close(injectionOutputFd);

		// Delete File
		remove(injectionOutputPipePath);
	}

	if (injectionInputFd)
		close(injectionInputFd);

	// Time measurement
	totalExecutionTime = timer.elapsed();

	return 0;
}
