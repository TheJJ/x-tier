#include "x-inject.h"

int main() {
	init_connection(8998);

	struct injection *injection = new_injection("/tmp/lsmod.inject");
	injection_load_code(injection);
	injection = consolidate(injection);

	struct received_data ret;
	ret.data = NULL;

	inject_module(injection, &ret);

	free_injection(injection);
	terminate_connection();

	// Time measurement
	print_injection_stats();

	return 0;
}
