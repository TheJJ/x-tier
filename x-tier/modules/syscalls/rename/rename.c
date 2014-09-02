#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/syscalls.h>

#include "../../inliner64.h"

long rename(char *oldname, char *newname)
{
	printk("renaming %s to %s\n", oldname, newname);
	return sys_rename(oldname, newname);
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
