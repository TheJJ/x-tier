#ifndef _X_INJECT_H_
#define _X_INJECT_H_

#include <stddef.h>
#include <QString>

#include "X-TIER.h"


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
			printf("[ x-inject - %s ] %d : %s(): " fmt, level_string, __LINE__, __func__, ##__VA_ARGS__);\
		}\
	} while (0)\

#define PRINT_DEBUG_FULL(fmt, ...) msg_print(ARR_DEBUG_FULL, "DEBUG FULL", fmt, ##__VA_ARGS__)
#define PRINT_DEBUG(fmt, ...)      msg_print(ARR_DEBUG, "DEBUG", fmt, ##__VA_ARGS__)
#define PRINT_INFO(fmt, ...)       msg_print(ARR_INFO, "INFO", fmt, ##__VA_ARGS__)
#define PRINT_WARNING(fmt, ...)    msg_print(ARR_WARNING, "WARNING", fmt, ##__VA_ARGS__)
#define PRINT_ERROR(fmt, ...)      msg_print(ARR_ERROR, "ERROR", fmt, ##__VA_ARGS__)


/**
 * data transfer file where x-tier puts it's stuff and sends it to us.
 */
const char *injection_output_pipe_filename = "/tmp/pipe_x-tier_to_ext";


/**
 * remembers the state of a opened file.
 *
 * each further call with the same file state then emulates
 * the "being open" by opening the fd again, and seeking.
 */
struct file_state {
	int fd;                //!< File pointer that we use for this file
	QString path;          //!< Path to the file
	int flags;             //!< Flags that were used to open the file
	int mode;              //!< Mode that was used to open the file
	unsigned int position; //!< Current position in the file in case of multiple reads
	unsigned int getdents; //!< Specifies if getdents is currently in progress
};

struct received_data {
	int   length;
	int   allocated;
	long  return_value;
	void *data;
};


bool inject_module(struct injection *injection, struct received_data *ret);
bool receive_data(struct received_data *ret);
void print_injection_stats(void);

bool send_monitor_command(const char *command);

bool init_connection(int16_t monitor_port);
void terminate_connection(void);


#endif
