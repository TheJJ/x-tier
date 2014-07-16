#include <stdio.h>
#include <unistd.h>

int main() {
	printf("ohai! you are %d\n", getuid());
	return 0;
}
