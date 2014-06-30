#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched.h>

#include <linux/syscalls.h>

#include <asm/fcntl.h>

long open(char *path, int flags, mode_t mode)
{
	long fd = sys_open(path, flags, mode);

	// Could not open file
	if (fd < 0) {
		return fd;
	}

	// Close
	sys_close(fd);

	// Return result
	return fd;
}

static int __init open_init(void)
{
	return 0;
}

static void __exit open_exit(void)
{
	return;
}

module_init(open_init);
module_exit(open_exit);

MODULE_LICENSE("GPL");
