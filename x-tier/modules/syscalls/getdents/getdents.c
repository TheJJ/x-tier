#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched.h>

#include <linux/syscalls.h>

#include <asm/fcntl.h>

#include "../../inliner64.h"

#define BUF_SIZE 4096

/*
 * struct linux_dirent
 *      Definition taken from  fs/readdir.c
 */
struct linux_dirent {
	unsigned long   d_ino;
	unsigned long   d_off;
	unsigned short  d_reclen;
	char            d_name[1];
};

long getdents(char *path)
{
	char buf[BUF_SIZE];
	long total_read = 0;
	long read = 0;

	int fd = sys_open(path, O_RDONLY|O_DIRECTORY, 0);

	// could not open file
	if (fd < 0) {
		return -1;
	}

	// read all available directory entry data
	while((read = sys_getdents(fd, (struct linux_dirent *)buf, BUF_SIZE)) > 0) {
		// Save total read bytes for return value
		total_read += read;

		// Send to hypervisor
		data_transfer(buf, read);
	}

	sys_close(fd);

	// Total data read
	if (read < 0)
		return read;
	else
		return total_read;
}

static int __init getdents_init(void)
{
	return 0;
}

static void __exit getdents_exit(void)
{
	return;
}

module_init(getdents_init);
module_exit(getdents_exit);

MODULE_LICENSE("GPL");
