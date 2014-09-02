#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/syscalls.h>

#include "../../inliner64.h"

long unlink(char *path)
{
	printk("deleting file %s\n", path);
	return sys_unlink(path);
}

static int __init mod_init(void)
{
	return 0;
}

static void __exit mod_exit(void)
{
	return;
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("GPL");
