#ifndef _X_INJECT_H_
#define _X_INJECT_H_

#include <stddef.h>
#include <string>
#include <cstring>

#include "X-TIER.h"
#include "error.h"

#define ARR_DEBUG_FULL 6
#define ARR_DEBUG 5
#define ARR_INFO 4
#define ARR_WARNING 3
#define ARR_ERROR 2
#define ARR_CRITICAL 1

#define DEBUG_LEVEL 6

#define msg_print(level, level_string, fmt, ...) \
	do {\
		if (DEBUG_LEVEL >= level) {\
			printf("[ libinject - %s ] %04d : %s(): " fmt, level_string, __LINE__, __func__, ##__VA_ARGS__);\
		}\
	} while (0)\

#define PRINT_DEBUG_FULL(fmt, ...) msg_print(ARR_DEBUG_FULL, "DEBUG+ ", fmt, ##__VA_ARGS__)
#define PRINT_DEBUG(fmt, ...)      msg_print(ARR_DEBUG,      "DEBUG  ", fmt, ##__VA_ARGS__)
#define PRINT_INFO(fmt, ...)       msg_print(ARR_INFO,       "INFO   ", fmt, ##__VA_ARGS__)
#define PRINT_WARNING(fmt, ...)    msg_print(ARR_WARNING,    "WARNING", fmt, ##__VA_ARGS__)
#define PRINT_ERROR(fmt, ...)      msg_print(ARR_ERROR,      "ERROR  ", fmt, ##__VA_ARGS__)


/**
 * data transfer file where x-tier puts it's stuff and sends it to us.
 */
#define injection_output_pipe_filename "/tmp/pipe_x-tier_to_ext"


struct received_data {
	received_data()
		:
		length(0),
		allocated(0),
		return_value(-1),
		data(nullptr) {}

	~received_data() {
		if (data != nullptr) {
			free(data);
		}
	}

	/** copy constructor */
	received_data(received_data const &other) {
		if (other.data != nullptr) {
			this->data = (char *)malloc(other.allocated * sizeof(char));
			memcpy(this->data, other.data, other.length);
		}
	}

	/** assignment op */
	received_data &operator=(received_data const &other) {
		if (this->data != nullptr) {
			free(this->data);
		}

		if (other.data != nullptr) {
			this->data = (char *)malloc(other.allocated * sizeof(char));
			memcpy(this->data, other.data, other.length);
		}
		return *this;
	}

	/** move constructor */
	received_data(received_data &&other) {
		this->data = other.data;
		other.data = nullptr;
	}


	int      length;
	int      allocated;
	int64_t  return_value;
	char     *data;
};


bool inject_module(struct injection *injection, struct received_data *ret);
bool receive_data(struct received_data *ret);
void print_injection_stats(void);

bool send_monitor_command(const char *command);

bool init_connection(int16_t monitor_port);
void terminate_connection(void);


#endif
