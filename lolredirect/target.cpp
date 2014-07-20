#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>


int main() {
	const char* filename = "/etc/passwd";

	int fd = open(filename, O_RDONLY);
	FILE *log = fopen("/tmp/log-NOFWD", "w");

	fprintf(log, "hai\n");
	int destfd = 1;

	struct stat s;
	memset(&s, 8, sizeof(struct stat));

	fprintf(log, "stat %d => store @ %p\n", fd, &s);
	fflush(log);

	stat(filename, &s);
	fprintf(log, "stated size: %ld\n", s.st_size);
	fflush(log);

	fstat(fd, &s);
	fprintf(log, "fd stated size: %ld\n", s.st_size);
	fflush(log);

	char *buf = (char *)malloc(s.st_size * sizeof(char));
	ssize_t n = read(fd, buf, s.st_size);
	fprintf(log, "read %zd bytes from %s\n", n, filename);
	fflush(log);

	n = write(destfd, buf, s.st_size);
	fprintf(log, "wrote %zd bytes to %d\n", n, destfd);
	fprintf(log, "done etc.\n");
	fflush(log);

	return 0;
}
