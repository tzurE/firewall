#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */ 
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h> 

/* index 1 is for the forward hook, index 2-3 is for input/output hooks*/
static struct nf_hook_ops hooks[3];

unsigned int block_hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
  printk(KERN_INFO "*** packet blocked ***\n");
  return NF_DROP;
}

unsigned int pass_hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
  printk(KERN_INFO "*** packet passed ***\n");
  return NF_ACCEPT;
}

int start_hooks(void){
	/* I have learned how to initialize the hook struct (what each field receives) using an example I found online.
	   A link to that example is provided at the Doc(1) */

	int i = 0, ret;

	hooks[0].hooknum = NF_INET_FORWARD;  		//use INET and not IP. IP is for userspace, INET is for kernel
	hooks[1].hooknum = NF_INET_LOCAL_IN;		//found this on linuxQuestions, a link is provided at the Doc(2)
	hooks[2].hooknum = NF_INET_LOCAL_OUT;

	for (i = 0; i < 3; i++){
		hooks[i].pf = PF_INET;					//IPV4 packets
		hooks[i].priority = NF_IP_PRI_FIRST;	//set to highest priority over all other hook functions
		if (i == 0)
			hooks[i].hook = block_hook_func; 	//function to call
		else
			hooks[i].hook = pass_hook_func;
		ret = nf_register_hook(&(hooks[i]));
		if (ret != 0) {
			return -1;
		}
	}
	return 0;
}

int close_hooks(void){
	int i = 0;
	/* unregister the functions. found this also at link (1) at the Doc.*/
	for (i = 0; i < 3; i++)
		nf_unregister_hook(&(hooks[i]));
	return 0;
}

int __init module_init_function(void) {

	if (start_hooks() == -1 ){
		printk(KERN_INFO "Register hook failed. existing..");
		close_hooks();
		return -1;
	}
	return 0;
}

void __exit module_exit_function(void) {
	close_hooks();
} 

/* As seen in class */
module_init(module_init_function);
module_exit(module_exit_function);