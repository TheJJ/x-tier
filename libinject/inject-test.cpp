#include "x-inject.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


int main() {
	init_connection(8998);

	struct injection *injection = new_injection("/tmp/stat.inject");

	injection_load_code(injection);

	const char *filename = "/etc/passwd";
	add_string_argument(injection, filename);
	injection = consolidate(injection);

	struct received_data ret;

	print_injection(injection);
	inject_module(injection, &ret);

	printf("injection return value %ld\n", ret.return_value);
	if (ret.data != NULL) {
		printf("inject test got data:\n%s\n", (char *) ret.data);

		struct stat *stat_result;

		stat_result = (struct stat *)ret.data;

		printf("statted %s:\n", filename);
		printf("inode number: %ld\n", stat_result->st_ino);
		printf("size: %zu\n", stat_result->st_size);
	}

	free_injection(injection);
	terminate_connection();

	print_injection_stats();

	return 0;
}
