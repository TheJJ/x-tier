#include "x-inject.h"

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

#include <QTime>

#include "X-TIER/X-TIER_external_command.h"


// qemu monitor connection vars
int  monitor_socket      = 0;
int  injection_output_fd = 0;
int  injection_input_fd  = 0;
bool created_output_pipe = false;

// time measurement vars
QTime timer;
long  tmpTime, tmpInjectionTime, tmpReceiveTime;
long  totalExecutionTime     = 0;
long  totalInjectionTime     = 0;
long  totalCommunicationTime = 0;
long  totalReceiveTime       = 0;
long  injectionCount         = 0;


bool create_injection_output_pipe(void) {
	int ret = 0;

	// Create named pipe - User Read, Write, Exec
	if (!created_output_pipe && (ret = mkfifo(injection_output_pipe_filename, S_IRWXU)) != 0) {
		if (errno != EEXIST) {
			PRINT_ERROR("Could not create named pipe '%s' (ret: %d, errno: %d)!\n",
			            injection_output_pipe_filename, ret, errno);
			return false;
		}
		PRINT_DEBUG_FULL("Created output fifo...\n");

	}

	created_output_pipe = true;
	return true;
}


bool open_injection_output_pipe(void) {
	// Open the fd
	if ((injection_output_fd = open(injection_output_pipe_filename, O_RDONLY)) < 0) {
		PRINT_ERROR("Could not open fd to named pipe '%s' (ret: %d, errno: %d)!\n",
		            injection_output_pipe_filename, injection_output_fd, errno);
		return false;
	}

	return true;
}


bool open_monitor_connection(int16_t port, const char *addr) {
	struct sockaddr_in server;

	// Create socket
	if ((monitor_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		PRINT_ERROR("Could not create socket!\n");
		return false;
	}

	// Configure
	server.sin_family      = AF_INET;
	server.sin_port        = htons(port);
	server.sin_addr.s_addr = inet_addr(addr);

	// Connect
	if (connect(monitor_socket, (struct sockaddr *)(&server), sizeof(server)) < 0) {
		PRINT_ERROR("Could not connect to server at port %d!\n", port);
		return false;
	}
	else {
		PRINT_INFO("connected to qemu monitor at port %d!\n", port);
		return true;
	}
}


bool send_monitor_command(const char *command) {
	if (!monitor_socket) {
		PRINT_ERROR("Could not connect to QEMU Monitor!\n");
		return false;
	}

	// Send command to qemu monitor
	// TODO: may be sending in multiple packets
	if (send(monitor_socket, command, strlen(command), 0) != (int)strlen(command)) {
		PRINT_ERROR("An error occurred while transmitting the '%s' command!\n", command);
		return false;
	}

	return true;
}


void realloc_recv_data(struct received_data *data) {
	void *tmp;

	const int factor = 2;

	if (data->length >= data->allocated) {
		tmp = realloc(data->data, data->allocated * factor);

		if (!tmp) {
			PRINT_ERROR("Could not increase data reception memory!\n");
			return;
		}

		data->allocated *= factor;
	}
}


int receive_data_chunk(struct received_data *data) {
	int n = 0;

	// Is the data buffer set up?
	if (!data->data) {
		data->allocated = 4096; //assume 4096
		data->length    = 0;    //nothing stored yet.

		data->data      = malloc(data->allocated);

		// Check allocation
		if (!data->data) {
			PRINT_ERROR("failed to allocate memory for received data!\n");
			return -1;
		}
	}

	// Do we have to extend the data buffer?
	realloc_recv_data(data);

	// Read data, maximum length equals free recv buffer memory size
	n = read(injection_output_fd, ((uint8_t *)data->data + data->length), (data->allocated - data->length));

	if (n < 0) {
		PRINT_ERROR("An error (%d) occurred while receiving the data!\n", n);
	}
	else {
		data->length += n;
	}

	return n;
}


bool receive_data(struct received_data *ret) {
	// len without \0
	const int data_begin_len = sizeof(XTIER_EXTERNAL_OUTPUT_BEGIN) - 1;
	const int data_end_len   = sizeof(XTIER_EXTERNAL_OUTPUT_END) - 1;
	char      data_begin[sizeof(XTIER_EXTERNAL_OUTPUT_BEGIN)];
	int       n              = 0;

	// First receive the output begin delimiter
	while ((n = read(injection_output_fd, data_begin, data_begin_len)) == 0) {}

	// Begin Time measurement
	tmpReceiveTime = timer.elapsed();

	if (n != data_begin_len) {
		PRINT_ERROR("An error occurred while receiving the data begin marker! "
		            "Received %d bytes instead of %d (errno: %d)\n",
		            n, data_begin_len, errno);
		return false;
	}

	if (strncmp(data_begin, XTIER_EXTERNAL_OUTPUT_BEGIN, data_begin_len) != 0) {
		PRINT_ERROR("Received string (%s) does not match begin marker!\n", data_begin);
		return false;
	}

	PRINT_DEBUG_FULL("Received begin marker!\n");


	// Receive data till we get the output delimiter
	PRINT_DEBUG_FULL("Beginning to receive data...\n");
	while (true) {
		PRINT_DEBUG_FULL("Receiving data chunk...\n");
		n = receive_data_chunk(ret);
		if (n >= 0) {
			PRINT_DEBUG_FULL("recieved %d bytes of data\n", n);
		}
		else {
			PRINT_ERROR("error %d encountered when reading data chunks\n", n);
			return false;
		}

		if (ret->length >= data_end_len) {
			//try to match the output delimiter and stop reading when found.
			if (0 == strncmp((char *)ret->data + (ret->length - data_end_len), XTIER_EXTERNAL_OUTPUT_END, data_end_len)) {
				break;
			}
		}
	}

	// remove the output delimiter from the read length to ignore it.
	ret->length -= data_end_len;

	// Receive return value
	ret->return_value  = XTIER_external_command_extract_return_value((char *)ret->data, ret->length);
	ret->length       -= XTIER_EXTERNAL_COMMAND_RETURN_VALUE_SIZE;
	PRINT_DEBUG("Received return value %ld!\n", ret->return_value);

	// Notice that we currently _NOT_ remove the end marker and the return value from the
	// received data. May be in the future.
	PRINT_DEBUG_FULL("Received end marker!\n");
	PRINT_DEBUG("Data tansfer of %ld bytes complete...\n", ret->length);

	// Time Measurement
	totalReceiveTime += (timer.elapsed() - tmpReceiveTime);

	return true;
}


bool inject_module(struct injection *injection, struct received_data *data) {
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
	if (!create_injection_output_pipe()) {
		PRINT_ERROR("Could not create output pipe!\n");
		return false;
	}

	// Prepare for external input
	PRINT_DEBUG_FULL("Sending Commands...\n");
	if (!send_monitor_command("x-tier\nexternal\n")) {
		return false;
	}

	// Open input pipe
	PRINT_DEBUG_FULL("Opening Input Pipe...\n");

	struct timespec input_pipe_delay {0, 100000000}; //0.1 s

	//TODO: race condition! wait for qemu to create the file!
	nanosleep(&input_pipe_delay, NULL);

	if (!injection_input_fd) {
		injection_input_fd = open(XTIER_EXTERNAL_COMMAND_PIPE, O_WRONLY);
	}

	if (injection_input_fd < 0) {
		PRINT_ERROR("Could not open fd to cmd input named pipe '%s'!\n", XTIER_EXTERNAL_COMMAND_PIPE);
		return false;
	}

	// Prepare cmd
	cmd.type = INJECTION;
	cmd.data_len = injection_size(injection);
	cmd.redirect = PIPE;

	// Prepare redirect
	re.type = PIPE;
	strcpy(re.filename, injection_output_pipe_filename);

	// Write cmd
	PRINT_DEBUG_FULL("Sending external command struct...\n");
	if (write(injection_input_fd, &cmd, sizeof(struct XTIER_external_command)) != sizeof(struct XTIER_external_command)) {
		PRINT_ERROR("An error occurred while writing the command struct. Aborting...\n");
		close(injection_input_fd);
		injection_input_fd = 0;
		return false;
	}

	//TODO: might be sent in multiple packets
	PRINT_DEBUG_FULL("Sending external commmand redirect struct...\n");
	if (write(injection_input_fd, &re, sizeof(struct XTIER_external_command_redirect)) != sizeof(struct XTIER_external_command_redirect)) {
		PRINT_ERROR("An error occurred while writing the redirect struct. Aborting...\n");
		close(injection_input_fd);
		injection_input_fd = 0;
		return false;
	}

	// Write injection
	PRINT_DEBUG_FULL("Sending injection...\n");
	injection_to_fd(injection, injection_input_fd);

	// run the injection!
	send_monitor_command("cont\n");

	// Time Measurement of the injection itself
	tmpInjectionTime = timer.elapsed();

	// Open output pipe
	if (injection_output_fd == 0) {
		if (!open_injection_output_pipe()) {
			PRINT_ERROR("An error occurred while opening the output pipe. Aborting...\n");
			return false;
		}
	}

	// receive data from the injection
	if (data == NULL) {
		PRINT_ERROR("destination receiving data struct is NULL!\n");
		return false;
	}

	if (!receive_data(data)) {
		return false;
	}

	// Time Measurement of the injection itself
	totalInjectionTime += (timer.elapsed() - tmpInjectionTime);

	//TODO: race condition again...
	nanosleep(&input_pipe_delay, NULL);

	// exit x-tier mode and resume vm
	send_monitor_command("cont\n");

	// Time measurement of the entire communication
	totalCommunicationTime += (timer.elapsed() - tmpTime);
	return true;
}


void print_injection_stats(void) {
	long s = 0;
	long ms = 0;

	totalExecutionTime = timer.elapsed();

	s  = totalExecutionTime / 1000;
	ms = totalExecutionTime - (s * 1000);
	printf("\n Execution: %lds %ldms\n", s, ms);

	s  = (totalCommunicationTime - totalInjectionTime + totalReceiveTime) / 1000;
	ms = (totalCommunicationTime - totalInjectionTime + totalReceiveTime) - (s * 1000);
	printf(" Communication: %lds %ldms\n", s, ms);

	s  = (totalReceiveTime) / 1000;
	ms = (totalReceiveTime) - (s * 1000);
	printf(" Receive: %lds %ldms\n", s, ms);

	s  = (totalInjectionTime - totalReceiveTime) / 1000;
	ms = (totalInjectionTime - totalReceiveTime) - (s * 1000);
	printf(" Injection: %lds %ldms\n", s, ms);
	printf("\tInjections: %ld\n", injectionCount);

	if (injectionCount > 0) {
		s  = ((totalInjectionTime - totalReceiveTime) / injectionCount) / 1000;
		ms = ((totalInjectionTime - totalReceiveTime) / injectionCount) - (s * 1000);
		printf("\tAverage: %lds %ldms\n", s, ms);
	}
}


void terminate_connection(void) {
	if (monitor_socket) {
		close(monitor_socket);
	}

	if (injection_output_fd) {
		close(injection_output_fd);
		remove(injection_output_pipe_filename);
	}

	if (injection_input_fd) {
		close(injection_input_fd);
	}
	PRINT_INFO("terminated connected to qemu monitor\n");
}

bool init_connection(int16_t port) {
	if (!open_monitor_connection(port, "127.0.0.1")) {
		return false;
	}

	timer.start();
	return true;
}
