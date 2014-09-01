#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched.h>

#include <linux/stat.h>
#include <linux/syscalls.h>

#include <asm/fcntl.h>

#include "../../inliner64.h"

#define BUF_SIZE 4096

// wrapper functions:
extern long XTIER_vfs_lstat(char *path, char *kstat, int kstat_size);
extern long cp_new_stat(struct kstat *k, struct stat *s, int kstat_size);

int lstat(char *path)
{
	struct stat s;
	struct kstat k;
	int result = 0;

	printk("running lstat on file %s\n", path);

	result = XTIER_vfs_lstat(path, (char *)&k, sizeof(struct kstat));

	if (result != 0) {
		return result;
	} else {
		result = cp_new_stat(&k, &s, sizeof(struct kstat));
		data_transfer((char *)&s, sizeof(struct stat));
		return result;
	}
}

static int __init stat_init(void)
{
	return 0;
}

static void __exit stat_exit(void)
{
	return;
}

module_init(stat_init);
module_exit(stat_exit);

MODULE_LICENSE("GPL");
