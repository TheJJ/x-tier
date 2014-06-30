#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/list.h>

static int __init lsmod_init(void)
{
	struct list_head *modules = (void *)0xffffffff81841d50;

	struct module *m;

	printk("Loaded Modules:\n\n");
	printk(" BASE ADDRESS \t   SIZE \t NAME\n");
	printk(" ------------ \t   ---- \t ----\n");

	list_for_each_entry(m, modules, list) {
		printk("%p \t % 7d \t %s\n", m->module_core, m->core_size, m->name);
	}

	return 0;
}

static void __exit lsmod_exit(void)
{
	return;
}

module_init(lsmod_init);
module_exit(lsmod_exit);

MODULE_LICENSE("GPL");
