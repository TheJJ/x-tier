#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched.h>

#include <linux/syscalls.h>
#include <asm/fcntl.h>

#include "../../inliner64.h"

#define WRITE_CHUNK_SIZE 1024

int write(char *path, int flags, int offset, char *buf, int bytes)
{
	int total_written = 0;
	int wrote = 0;
	int result = 0;

	int fd = sys_open(path, flags, 0);
	printk("write: open %s = %d\n", path, fd);

	if (fd < 0) {
		return -1;
	}

	// seek to requested data beginning
	if (offset > 0) {
		printk("seeking to offset %d\n", offset);
		if ((result = sys_lseek(fd, offset, SEEK_SET)) < 0) {
			return result;
		}
	}

	// start writing data
	do {
		int to_write;
		if ((bytes - total_written) > WRITE_CHUNK_SIZE) {
			to_write = WRITE_CHUNK_SIZE;
		}
		else {
			to_write = (bytes - total_written);
		}

		// slide the buffer beginning.
		buf += wrote;

		// call kernel's write function
		printk("calling sys_write(fd=%d, buf=%p, count=%d):\n", fd, buf, to_write);
		wrote = sys_write(fd, buf, to_write);
		total_written += wrote;

	} while (wrote > 0 && total_written < bytes);

	sys_close(fd);

	if (wrote < 0) {
		return wrote;
	}
	else {
		return total_written;
	}
}

static int __init read_init(void)
{
	return 0;
}

static void __exit read_exit(void)
{
	return;
}

module_init(read_init);
module_exit(read_exit);

MODULE_LICENSE("GPL");
