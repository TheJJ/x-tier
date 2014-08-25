#include <linux/module.h>
#include <linux/init.h>
#include <linux/utsname.h>

#include "../../inliner64.h"

extern int sys_newuname(struct new_utsname *name);

long uname(void) {
	struct new_utsname result;

	int ret = sys_newuname(&result);

	data_transfer((char *)&result, sizeof(result));
	return ret;
}


static int __init uname_init(void)
{
	return 0;
}

static void __exit uname_exit(void)
{
	return;
}

module_init(uname_init);
module_exit(uname_exit);

MODULE_LICENSE("GPL");
