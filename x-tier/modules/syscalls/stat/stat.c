#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched.h>

#include <linux/stat.h>
#include <linux/syscalls.h>

#include <asm/fcntl.h>

#include "../../inliner64.h"

#define BUF_SIZE 4096

extern long XTIER_vfs_stat(char *path, char *kstat, int kstat_size);
extern long cp_new_stat(struct kstat *k, struct stat *s, int kstat_size);

int stat(char *path)
{
	struct stat s;
	struct kstat k;
	int result = 0;

	printk("running stat on file %s\n", path);

	result = XTIER_vfs_stat(path, (char *)&k, sizeof(struct kstat));

	printk("xtier vfs stat executed on %s\n", path);

	if (result != 0) {
		return result;
	} else {
		// Convert kstat struct to stat struct
		printk("UID %d\n", k.uid.val);
		result = cp_new_stat(&k, &s, sizeof(struct kstat));
		printk("new UID %d\n", s.st_uid);
		printk("transfering back the stat struct...\n");
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
