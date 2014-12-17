#include <fcntl.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "/usr/src/linux/include/uapi/linux/x-tier.h"


#define PRINT(fmt, ...) printf(fmt, ##__VA_ARGS__)
#define MALLOC(x) malloc((x));
#define FREE(x) free(x);

/*
 * +=========================================================
 * |                    DEBUG
 * +=========================================================
 */
#define INJECTION_DEBUG_FULL 6
#define INJECTION_DEBUG 5
#define INJECTION_INFO 4
#define INJECTION_WARNING 3
#define INJECTION_ERROR 2
#define INJECTION_CRITICAL 1

#define DEBUG_LEVEL 6

#define msg_print(level, level_string, fmt, ...)                        \
	do { if (DEBUG_LEVEL >= level) PRINT("[ Injection - %s ] %d : %s(): " fmt, \
	                                     level_string, __LINE__, __func__, ##__VA_ARGS__); } while (0)

#define PRINT_DEBUG_FULL(fmt, ...) msg_print(INJECTION_DEBUG_FULL, "DEBUG FULL", fmt, ##__VA_ARGS__)
#define PRINT_DEBUG(fmt, ...) msg_print(INJECTION_DEBUG, "DEBUG", fmt, ##__VA_ARGS__)
#define PRINT_INFO(fmt, ...) msg_print(INJECTION_INFO, "INFO", fmt, ##__VA_ARGS__)
#define PRINT_WARNING(fmt, ...) msg_print(INJECTION_WARNING, "WARNING", fmt, ##__VA_ARGS__)
#define PRINT_ERROR(fmt, ...) msg_print(INJECTION_ERROR, "ERROR", fmt, ##__VA_ARGS__)


/*
 * +=========================================================
 * |                    LIST HELPERS
 * +=========================================================
 */
static void insert_arg(struct injection *injection, struct injection_arg *arg)
{
	unsigned int i = 0;
	struct injection_arg *tmp_arg = NULL;

	// Insert
	tmp_arg = injection->argv;

	// List is empty at the moment, insert the first argument
	if (injection->argc == 0) {
		arg->next = arg;
		arg->prev = arg;
		injection->argv = arg;

		goto out;
	}

	// Find place for inserting new argument
	for (i = 0; i < injection->argc; i++, tmp_arg = tmp_arg->next) {
		if (tmp_arg->number > arg->number) {
			// New element goes here
			arg->next = tmp_arg;
			arg->prev = tmp_arg->prev;
			tmp_arg->prev = arg;
			arg->prev->next = arg;
		}
		else if (i + 1 == injection->argc) {
			// Last slot
			arg->next = tmp_arg->next;
			arg->prev = tmp_arg;
			tmp_arg->next = arg;
			arg->next->prev = arg;
		}
	}

out:
	injection->argc += 1;
	return;
}

/*
 * +=========================================================
 * |                    ITERATION HELPERS
 * +=========================================================
 */


static struct injection_arg *get_first_injection_arg(struct injection *injection)
{
	if (injection->argc == 0) {
		PRINT_ERROR("queried first injection argument where argc == 0!\n");
		return NULL;
	}

	if ((injection->type & (CONSOLIDATED))) {
		return (struct injection_arg *)((char *)injection + injection_size(injection) - injection->args_size);
	}
	else {
		return injection->argv;
	}
}

static struct injection_arg *get_last_injection_arg(struct injection *injection)
{
	if (injection->argc == 0) {
		PRINT_ERROR("queried last injection argument where argc == 0!\n");
		return NULL;
	}

	if ((injection->type & (CONSOLIDATED))) {
		return (struct injection_arg *)((char *)injection + injection_size(injection) - injection->size_last_arg);
	}
	else {
		if (injection->argv) {
			if (injection->type & (CONSOLIDATED_ARGS)) {
				return (struct injection_arg *)((char *)injection->argv + injection->args_size - injection->size_last_arg);
			}
			else {
				return injection->argv->prev;
			}
		}
		else {
			PRINT_ERROR("injection argv is NULL even though argc != 0!\n");
			return NULL;
		}
	}
}

struct injection_arg *get_next_arg(struct injection *injection,
                                   struct injection_arg *arg)
{
	struct injection_arg *ret = NULL;

	// If no previous arg was queried, return the first arg
	if (arg == NULL) {
		ret = get_first_injection_arg(injection);
	}
	else if (injection->argc == 1) {
		ret = arg;
	}
	else if ((injection->type & (CONSOLIDATED | CONSOLIDATED_ARGS))) {
		//next argument is located after the size of this argument + its data
		ret = (struct injection_arg *)(((char *)arg) + sizeof(struct injection_arg) + arg->size);
	}
	else {
		ret = arg->next;
	}

	return ret;
}

struct injection_arg *get_prev_arg(struct injection *injection,
                                   struct injection_arg *arg)
{
	struct injection_arg *ret = NULL;

	// If arg is NULL we return the last arg
	if (arg == NULL) {
		ret = get_last_injection_arg(injection);
	}
	else if (injection->argc == 1) {
		ret = arg;
	}
	else if ((injection->type & (CONSOLIDATED | CONSOLIDATED_ARGS))) {
		ret = (struct injection_arg *)(((char *)arg) - (sizeof(struct injection_arg) + arg->size_prev));
	}
	else {
		ret = arg->prev;
	}

	return ret;
}

/**
   return pointer to the argument data.
 */
char *get_arg_data(struct injection *injection, struct injection_arg *arg)
{
	//when serialized, the arg data is stored right behind the injection_arg structure.
	if ((injection->type & (CONSOLIDATED | CONSOLIDATED_ARGS))) {
		return (char *)(((char *)arg) + sizeof(struct injection_arg));
	}
	else {
		return arg->data;
	}
}

/*
 * +=========================================================
 * |                    CREATION HELPERS
 * +=========================================================
 *
 */

static void injection_set_module_name(struct injection *injection, const char *module)
{
	// Allocate name
	injection->path_len = strlen(module) + 1;
	injection->module_path = (char *)MALLOC(injection->path_len);

	// Check allocation
	if (!injection->module_path)
	{
		PRINT_ERROR("Could not allocated memory!\n");
		return;
	}

	strcpy(injection->module_path, module);
}


int injection_load_code(struct injection *injection)
{
	struct stat stbuf;
	FILE *file;
	int fd = 0;

	// Free existing data if any
	if (injection->code) {
		FREE(injection->code)
	}

	// Make sure injection is NULL
	injection->code = NULL;

	if (!injection->module_path)
	{
		PRINT_ERROR("Injection structure has no module set! Cannot load code!\n");
		return 1;
	}

	// Open File Descriptor
	fd = open(injection->module_path, O_RDONLY);

	if(fd < 0)
	{
		PRINT_ERROR("Could not open file descriptor to file %s!\n", injection->module_path);
		return 1;
	}

	// Open file
	file = fdopen(fd, "rb");

	if (!file)
	{
		PRINT_ERROR("Could not open file %s!\n", injection->module_path);
		return 1;
	}

	// Get length of the file
	if (fstat(fd, &stbuf) == -1)
	{
		PRINT_ERROR("Could not obtain the size of the file!\n");
		return 1;
	}

	injection->code_len = stbuf.st_size;

	// Reserve memory
	injection->code = (char *)MALLOC(injection->code_len + 1);

	if (!injection->code)
	{
		PRINT_ERROR("Could not reserve memory!\n");

		fclose(file);
		return 1;
	}

	// Read file
	if(fread(injection->code, 1, injection->code_len, file) != injection->code_len)
	{
		PRINT_ERROR("An error occurred while reading the injection file '%s'\n", injection->module_path);
		return 1;
	}

	fclose(file);
	return 0;
}

struct injection *new_injection(const char *module_name)
{
	struct injection *result = (struct injection *)MALLOC(sizeof(struct injection));

	if (!result) {
		PRINT_ERROR("Could not allocated memory!\n");
		return result;
	}

	memset(result, 0, sizeof(struct injection));

	// Name
	injection_set_module_name(result, module_name);

	// Set Type
	result->type = VARIABLE;

	// Generals
	result->code                 = NULL;
	result->code_len             = 0;
	result->event_based          = 0;
	result->event_address        = NULL;
	result->auto_inject          = 0;
	result->time_inject          = 0;
	result->exit_after_injection = 1;

	// injection arguments
	result->args_size     = 0;
	result->size_last_arg = 0;
	result->argc          = 0;
	result->argv          = NULL;

	return result;
}

static void consolidated_update_pointers(struct injection *injection);

void injection_to_fd(struct injection *injection, int fd)
{
	unsigned int size = 0;

	if (!injection) {
		PRINT_ERROR("Given injection pointer is NULL!\n");
		return;
	}

	if (injection->type != CONSOLIDATED) {
		PRINT_ERROR("Only consolidated structures can be written to an fd!\n");
		return;
	}

	// Write the injection struct
	if (write(fd, injection, sizeof(struct injection)) != sizeof(struct injection)) {
		PRINT_ERROR("Could not write injection struct!\n");
		return;
	}

	// Write data
	size = injection_size(injection) - sizeof(struct injection);
	if (write(fd, (((char *)injection) + sizeof(struct injection)), size) != size) {
		PRINT_ERROR("Could not write injection data!\n");
		return;
	}
}

struct injection *injection_from_fd(int fd)
{
	struct injection injection;
	struct injection *result = NULL;
	int size = 0;
	int ret = 0;

	// Obtain the injection struct
	PRINT_DEBUG_FULL("Obtaining the injection struct...\n");
	if ((ret = read(fd, &injection, sizeof(struct injection))) != sizeof(struct injection)) {
		PRINT_ERROR("Could not obtain injection struct! (read %d bytes instead of %ld bytes)\n",
		            ret, sizeof(struct injection));
		return NULL;
	}

	// Reserve space
	size = injection_size(&injection);
	result = (struct injection *)MALLOC(size);

	if (!result) {
		PRINT_ERROR("Could not allocated memory!\n");
		return NULL;
	}

	// Copy struct to buffer
	memcpy(result, &injection, sizeof(struct injection));

	// Get remaining data from fd
	PRINT_DEBUG_FULL("Obtaining injection data...\n");
	size -= sizeof(struct injection);
	if ((ret = read(fd, (((char *)result) + sizeof(struct injection)), size)) != size) {
		PRINT_ERROR("Could not obtain injection data! (read %d bytes instead of %d bytes)\n",
		            ret, size);
	}

	// Update Pointers
	PRINT_DEBUG_FULL("Updating pointers...\n");
	consolidated_update_pointers(result);

	return result;
}

static struct injection_arg *new_injection_arg(void)
{
	size_t memsize = sizeof(struct injection_arg);
	struct injection_arg *result = (struct injection_arg *)MALLOC(memsize);
	memset((char *)result, 0, memsize);

	if (!result)
	{
		PRINT_ERROR("Could not allocated memory!\n");
		return result;
	}

	result->number = 0;
	result->type = UNDEFINED;
	result->size = 0;
	result->next = NULL;
	result->prev = NULL;
	result->data = NULL;

	return result;
}

static void free_injection_args(struct injection *injection)
{
	struct injection_arg *next = NULL;
	struct injection_arg *cur = NULL;
	unsigned int i = 0;

	// injection arguments
	if (injection->argc > 0) {
		//only free argument components if they were not consolidated
		if (!(injection->type & CONSOLIDATED_ARGS)) {
			cur = get_first_injection_arg(injection);

			for (i = 0; i < injection->argc; ++i) {
				next = cur->next; //remember the next

				FREE(cur->data);
				FREE(cur);

				cur = next; //go to the next
			}
		}
	}
}

void free_injection(struct injection *injection)
{
	if (!(injection->type & (CONSOLIDATED))) {
		//free components if injection is not consolidated
		free_injection_args(injection);
		FREE(injection->module_path);
		FREE(injection->code);
	}

	FREE(injection);
}


void free_injection_without_code(struct injection *injection)
{
	if (!(injection->type & CONSOLIDATED))
	{
		free_injection_args(injection);
		FREE(injection->module_path);
	}

	FREE(injection);
}


/*
 * +=========================================================
 * |                   CONSOLIDATION
 * +=========================================================
 */

unsigned int injection_size(struct injection *injection)
{
	unsigned int total_size = 0;

	total_size += sizeof(struct injection);

	// Module name
	total_size += injection->path_len;

	// Code len
	total_size += injection->code_len;

	// Args
	total_size += injection->args_size;

	return total_size;
}

// Fixes the argument pointers in a consolidated injection structure
void consolidated_update_arg_pointers(struct injection *injection)
{
	/*
	  consolidated_args:
	  ######### <- injection blob
	          | <- argv ptr
	          v
	          #%%#%%%#%%
	          ^ \_ injection_arg data
	          injection_arg

	  consolidated:

	  ##########%%#%%%#%%

	 */
	struct injection_arg *cur, *prev, *last;

	if (injection->argc > 0) {
		//when CONSOLIDATED, cur is the offset within the injection blob
		//else cur is the current (new) arg start pointer
		cur = get_first_injection_arg(injection);

		//set the new arg start ptr to that point
		injection->argv = cur;

		//get new last injection arg ptr
		last = get_last_injection_arg(injection);

		//current arg is the first.
		//the previous to the first arg is the last
		prev = last;

		if (!cur) {
			//no arguments stored.
			return;
		}

		do {
			// Set previous arg ptr for the current arg
			cur->prev = prev;

			// The next of the previous arg is the current arg
			prev->next = cur;

			// The arg data may lie behind the arg metadata structure
			cur->data = get_arg_data(injection, cur);

			// Move onto the next arg
			prev = cur;
			cur = get_next_arg(injection, cur);
		}
		while (prev != last);
	}
	else {
		injection->argv = NULL;
	}
}

// Fixes the pointers in a consolidated injection structure
static void consolidated_update_pointers(struct injection *injection)
{
	// Structure consolidated? pointer update only makes sense for blob
	if (injection->type != CONSOLIDATED) {
		PRINT_WARNING("This is not a consolidated injection structure!\n");
		return;
	}

	// the module name is stored right behind the injection structure
	if (injection->path_len) {
		injection->module_path = ((char *)injection) + sizeof(struct injection);
	}
	else {
		injection->module_path = NULL;
	}

	// the code is stored right after the module name
	if (injection->code_len) {
		injection->code = ((char *)injection->module_path) + injection->path_len;
	}
	else {
		injection->code = NULL;
	}

	// the argument data, should be right after the code
	if (injection->argc > 0) {
		injection->argv = get_first_injection_arg(injection);
	}

	consolidated_update_arg_pointers(injection);
}

/**
 * Helper that consolidates the arguments only. Notice that this function does _NOT_
 * update the argument pointers. To achieve this the consolidated_update_arg_pointers
 * funciton can be used. Further the function does _NOT_ update the type of the injection
 * structure nor the original unconsolidated arguments.
 */
struct injection_arg *get_consolidated_args(struct injection *injection, char *consolidated_data_dest_ptr)
{
	struct injection_arg *result = NULL;
	struct injection_arg *arg = NULL;
	unsigned int i = 0;

	if (injection->argc > 0) {
		//return the descination position as result.
		result = (struct injection_arg *)consolidated_data_dest_ptr;

		// copy each argument
		arg = get_first_injection_arg(injection);

		for (i = 0; i < injection->argc; arg = get_next_arg(injection, arg), ++i) {
			memcpy(consolidated_data_dest_ptr, arg, sizeof(struct injection_arg));

			//set linked list pointers to NULL
			((struct injection_arg *)consolidated_data_dest_ptr)->next = NULL;
			((struct injection_arg *)consolidated_data_dest_ptr)->prev = NULL;
			((struct injection_arg *)consolidated_data_dest_ptr)->data = NULL;

			//move storage pointer behind current copied argument structure
			consolidated_data_dest_ptr += sizeof(struct injection_arg);

			//store the argument data right behinnd the injection_arg structure
			//belonging to it.
			memcpy(consolidated_data_dest_ptr, arg->data, arg->size);
			consolidated_data_dest_ptr += arg->size;
		}
	}

	return result;
}

//create a blob for all the injection argument data
struct injection *consolidate_args(struct injection *injection)
{
	char *consolidated_data = NULL;
	struct injection_arg *consolidated_args = NULL;

	// Is this structure already a blob including the arguments
	if (injection->type & CONSOLIDATED) {
		PRINT_WARNING("Injection structure already consolidated! Aborting!\n");
		return injection;
	}

	// Allocate memory for arg blob
	consolidated_data = (char *)MALLOC(injection->args_size);

	if (!consolidated_data) {
		PRINT_ERROR("Could not allocated memory for argument data!\n");
		return injection;
	}

	// Get consolidated arguments
	consolidated_args = get_consolidated_args(injection, consolidated_data);

	// Free original args
	free_injection_args(injection);

	// Update args and pointers
	injection->type = CONSOLIDATED_ARGS;
	injection->argv = consolidated_args;
	consolidated_update_arg_pointers(injection);

	return injection;
}

struct injection *consolidate(struct injection *injection)
{
	char *consolidated_data = NULL;
	struct injection *result = NULL;

	size_t blob_size = injection_size(injection);

	// Is this structure already consolidated?
	if (injection->type & (CONSOLIDATED)) {
		PRINT_WARNING("Injection structure already consolidated! Aborting!\n");
		return injection;
	}

	if (injection->code_len <= 0) {
		PRINT_WARNING("Injection code length is <= 0\n");
	}

	// Allocate memory for the whole injection blob
	// this includes metadata, module name, code and arguments
	consolidated_data = (char *)MALLOC(blob_size);

	if (!consolidated_data) {
		PRINT_ERROR("Could not allocated memory!\n");
		return injection;
	}

	result = (struct injection *)consolidated_data;

	// Set & Copy Injection
	memcpy(consolidated_data, injection, sizeof(struct injection));
	consolidated_data += sizeof(struct injection);

	// Copy Module Name
	memcpy(consolidated_data, injection->module_path, result->path_len);
	result->module_path = NULL;
	consolidated_data += result->path_len;

	// Copy code
	memcpy(consolidated_data, injection->code, result->code_len);
	result->code = NULL;
	consolidated_data += result->code_len;

	// Consolidate arguments, store them behind the code
	result->argv = get_consolidated_args(injection, consolidated_data);

	// Free old injection structure
	free_injection(injection);

	result->type = CONSOLIDATED;

	// Fix pointers
	consolidated_update_pointers(result);

	return result;
}

/*
 * +=========================================================
 * |                    ARG HELPERS
 * +=========================================================
 */
static void add_argument(struct injection *injection, unsigned int number,
                         enum arg_type type, unsigned int size, const char *data)
{
	struct injection_arg *arg;

	// Cannot add arguments to a consolidated injection
	if (injection->type & (CONSOLIDATED | CONSOLIDATED_ARGS)) {
		PRINT_ERROR("Injection structure is consolidated! Cannot add new arguments!\n");
		return;
	}

	// Create arg
	arg = new_injection_arg();

	if (!arg) {
		PRINT_ERROR("An error occurred while allocating the argument!\n");
		return;
	}

	// Set values
	arg->number = number;
	arg->type = type;
	arg->size = size;

	// Set data
	// We store all NUMERIC data types in 8 bytes of memory
	if (size < 8) {
		arg->data = (char *)MALLOC(8 * sizeof(char));
		memset(arg->data, 0, 8);
	}
	else {
		arg->data = (char *)MALLOC(size * sizeof(char));
	}

	if (!arg->data) {
		PRINT_ERROR("An error occurred while allocating space for the data of the argument!\n");
		return;
	}

	//store argument data
	memcpy(arg->data, data, size);

	// Insert the arg, updates ->prev, ->next etc
	insert_arg(injection, arg);

	// Notice that this will be incorrect for a single element
	arg->size_prev = arg->prev->size;

	injection->args_size     += sizeof(struct injection_arg) + size;
	injection->size_last_arg  = sizeof(struct injection_arg) + injection->argv->prev->size;
}

static unsigned int next_free_arg_number(struct injection *injection)
{
	return injection->argc;
}

/*
 * +=========================================================
 * |                    NUMERIC HELPERS
 * +=========================================================
 *
 * Fix sizes for 32-bit systems.
 *
 */
void add_char_argument(struct injection *injection, char data)
{
	add_argument(injection, next_free_arg_number(injection), NUMERIC, sizeof(char), &data);
}

void add_short_argument(struct injection *injection, short data)
{
	add_argument(injection, next_free_arg_number(injection), NUMERIC, sizeof(short), (char *)&data);
}

void add_int_argument(struct injection *injection, int data)
{
	add_argument(injection, next_free_arg_number(injection), NUMERIC, sizeof(int), (char *)&data);
}

void add_long_argument(struct injection *injection, long data)
{
	add_argument(injection, next_free_arg_number(injection), NUMERIC, sizeof(long), (char *)&data);
}


/*
 * +=========================================================
 * |                    STRING HELPERS
 * +=========================================================
 */
void add_string_argument(struct injection *injection, const char *data)
{
	unsigned int len = strlen(data) + 1;

	add_argument(injection, next_free_arg_number(injection), STRING, len, data);
}

/*
 * +=========================================================
 * |                    STRUCT HELPERS
 * +=========================================================
 */
void add_struct_argument(struct injection *injection, void *data, unsigned int size)
{
	add_argument(injection, next_free_arg_number(injection), STRUCTURE, size, (char *)data);
}

/*
 * +=========================================================
 * |                    UTILITY FUNCTIONS
 * +=========================================================
 *
 */
char is_immediate(struct injection_arg *arg)
{
	if (arg == NULL) {
		return -1;
	}

	switch (arg->type) {
	case NUMERIC:
		return 1;
	case STRING:
	case STRUCTURE:
		return 0;
	default:
		return 0;
	}
}

const char *argument_type_to_string(enum arg_type type)
{
	switch (type) {
	case NUMERIC:
		return "NUMERIC";
	case STRING:
		return "STRING";
	case STRUCTURE:
		return "STRUCTURE";
	default:
		return "UNDEFINED";
	}
}

void print_argument_data(struct injection *injection, struct injection_arg *arg)
{
	char *arg_data = get_arg_data(injection, arg);

	switch (arg->type) {
	case NUMERIC:
		switch (arg->size) {
		case sizeof(char):
			PRINT("\t\t DATA: %c\n", *arg_data);
			return;
		case sizeof(short):
			PRINT("\t\t DATA: %hd\n", *((short *)arg_data));
			return;
		case sizeof(int):
			PRINT("\t\t DATA: %d\n", *((int *)arg_data));
			return;
		case sizeof(long):
			PRINT("\t\t DATA: %ld\n", *((long *)arg_data));
			return;
		default:
			PRINT("\t\t DATA: UNKNOWN NUMERIC SIZE!\n");
			return;
		}
	case STRING:
		PRINT("\t\t DATA: %s\n", arg_data);
		return;
	case STRUCTURE:
		PRINT("\t\t DATA: 0x%llx\n", *((long long *)arg_data));
		return;
	default:
		PRINT("\t\t DATA: UNDEFINED!\n");
		return;
	}
}

void print_argument(struct injection *injection, struct injection_arg *arg)
{
	PRINT("\t ARGUMENT %d @ %p\n", arg->number, arg);
	PRINT("\t\t TYPE: %s\n", argument_type_to_string(arg->type));
	PRINT("\t\t SIZE: %d\n", arg->size);
	PRINT("\t\t NEXT: %p\n", arg->next);
	PRINT("\t\t PREV: %p\n", arg->prev);
	PRINT("\t\t DATA @%p\n", arg->data);
	print_argument_data(injection, arg);
}

void print_arguments(struct injection *injection)
{
	struct injection_arg *arg = NULL;
	unsigned int i = 0;

	PRINT("arguments:\n");
	PRINT("\tlen(arguments): %d (argv @ %p)\n", injection->argc, get_first_injection_arg(injection));

	for (i = 0; i < injection->argc; ++i) {
		arg = get_next_arg(injection, arg);

		if (arg == NULL) {
			PRINT_ERROR("Error: injection argument %d is nullptr!\n", i);
			return;
		}

		print_argument(injection, arg);
	}
}

void print_arguments_reverse(struct injection *injection)
{
	struct injection_arg *arg = NULL;
	unsigned int i = 0;

	PRINT("arguments: reverse order\n");
	PRINT("\tlen(arguments): %d (argv @ %p)\n", injection->argc, get_first_injection_arg(injection));

	for (i = 0; i < injection->argc; ++i)
	{
		arg = get_prev_arg(injection, arg);
		if (arg == NULL) {
			PRINT_ERROR("Error: injection argument %d is nullptr!\n", i);
			return;
		}

		print_argument(injection, arg);
	}
}


static void _print_injection(struct injection *injection, int order)
{
	PRINT("INJECTION STRUCTURE\n");
	PRINT("===================\n");
	PRINT("\t MODULE: %s\n", injection->module_path);

	if (injection->type == VARIABLE)
		PRINT("\t TYPE: VARIABLE\n");
	else if (injection->type == CONSOLIDATED_ARGS)
		PRINT("\t TYPE: CONSOLIDATED ARGS\n");
	else if (injection->type == CONSOLIDATED)
		PRINT("\t TYPE: CONSOLIDATED\n");
	else
		PRINT("\t TYPE: UNDEFINED\n");

	PRINT("\t TOTAL SIZE: %d\n", injection_size(injection));

	PRINT("\t CODE:        @ 0x%p\n", injection->code);
	PRINT("\t CODE LEN:      %d\n", injection->code_len);
	PRINT("\t ARGUMENTS:   @ 0x%p\n", injection->argv);
	PRINT("\t ARGS SIZE:     %d\n", injection->args_size);
	//PRINT("\t EVENT BASED:   %d\n", injection->event_based);
	//PRINT("\t EVENT ADDRESS: 0x%p\n", injection->event_address);
	//PRINT("\t TIME BASED:    %d\n", injection->time_inject);
	//PRINT("\t AUTO INJECT:   %d\n", injection->auto_inject);
	PRINT("\t EXIT AFTER INJECTION: %d\n", injection->exit_after_injection);

	if (order > 0)
		print_arguments(injection);
	else
		print_arguments_reverse(injection);
}

void print_injection(struct injection *injection)
{
	_print_injection(injection, 1);
}

void print_injection_reverse(struct injection *injection)
{
	_print_injection(injection, -1);
}
