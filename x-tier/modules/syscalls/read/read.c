#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched.h>

#include <linux/syscalls.h>

#include <asm/fcntl.h>

#include "../../inliner64.h"

#define BUF_SIZE 1024

long read(char *path, int flags, int offset, int bytes)
{
	char buf[BUF_SIZE];
	long total_read = 0;
	long read = 0;
	long result = 0;

	int fd = sys_open(path, flags, 0);
	printk("read: open %s = %d\n", path, fd);

	// could not open file
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

	// start reading data
	do {
		printk("calling sys_read(fd=%d, buf=%p, bufsize=%d):\n", fd, buf, BUF_SIZE);

		//call kernel's read function
		read = sys_read(fd, buf, BUF_SIZE);

		printk("sys_read returned %ld\n", read);

		if (read < 0) {
			break;
		}

		// save total read bytes for return value
		total_read += read;

		// send to hypervisor
		printk("sending data buffer (ret=%ld)...\n", read);
		data_transfer(buf, read);

		// check if there is no more data
		if (read < BUF_SIZE) {
			break;
		}
	} while (read > 0 && total_read < bytes);

	// close fd on guest kernel
	sys_close(fd);

	// total data read
	if (read < 0) {
		return read;
	}
	else {
		return total_read;
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
