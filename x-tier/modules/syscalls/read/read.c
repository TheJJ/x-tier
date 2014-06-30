#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched.h>

#include <linux/syscalls.h>

#include <asm/fcntl.h>

#include "../../inliner64.h"

#define BUF_SIZE 1024

int read(char *path, int flags, int offset, int bytes)
{
	char buf[BUF_SIZE];
	int total_read = 0;
	int read = 0;
	int result = 0;

	int fd = sys_open(path, flags, 0);

	// Could not open file
	if (fd < 0)
		return -1;

	// Seek
	if (offset > 0) {
		if ((result = sys_lseek(fd, offset, SEEK_SET)) < 0)
			return result;
	}

	// Read data
	while((read = sys_read(fd, buf, BUF_SIZE)) > 0 &&
	      total_read < bytes)
	{

		printk("reading...\n");

		// Save total read bytes for return value
		total_read += read;

		// Send to hypervisor
		data_transfer(buf, read);

		// Check if there is no more data
		if (read < BUF_SIZE)
			break;
	}

	// Close
	sys_close(fd);

	// Total data read
	if (read < 0)
		return read;
	else
		return total_read;
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
