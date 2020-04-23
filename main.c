/*
* main.c - basic kernel module
*/

#include <linux/module.h>  // Needed by all kernel modules
#include <linux/kernel.h>  // Needed for KERN_INFO
#include <linux/init.h>    // Needed for macros

static int __init start_module(void) {
	printk(KERN_INFO "Hello world 1.\n");
	return 0;
}

static void __exit stop_module(void) {
	printk(KERN_INFO "Goodbye world 1.\n");
}

module_init(start_module);
module_exit(stop_module);