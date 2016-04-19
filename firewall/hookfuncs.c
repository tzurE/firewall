#include "hookfuncs.h"
#include "fw.h"


/* index 1 is for the forward hook, index 2-3 is for input/output hooks
more on this at the Doc added */
struct nf_hook_ops hooks[3];
int cnt_blocked = 0, cnt_accepted = 0;
extern int firewall_activated;

int packet_get(struct sk_buff *skb, const struct net_device *in, unsigned int hooknum, int dir){
	rule_t packet;
	struct iphdr *iphd;
	struct tcphdr *tcphd;
	struct udphdr *udphd;

	iphd = ip_hdr(skb)
	//if dir = 20 then it's input. else it's 0 then it's output
	tcphd = (struct tcphdr *)(skb_transport_header(skb)+dir)
	udphd = (struct udphdr *)(skb_transport_header(skb)+dir)

	input.src_ip = iphd->saddr;
	printk("%d\n", input.src_ip);
}

unsigned int input_hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
  // struct tcphdr *tcp;
  // char source[16];
  // struct iphdr *ip;
  // ip = ip_hdr(skb);
  // int src_ip = ip->saddr;
  // snprintf(source, 16, "%pI4", &ip->saddr); // Mind the &!
  // printk(KERN_INFO "*** input packet ***\n");
  
  // printk(source);
  // printk(KERN_INFO "\n");
  // cnt_blocked++;
  return packet_get(skb, in, hooknum, 20);
}

unsigned int output_hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
  printk(KERN_INFO "*** output packet ***\n");
  cnt_accepted++;
  return NF_ACCEPT;
}


int start_hooks(void){
	printk(KERN_INFO "Activating firewall");
	int i = 0, ret;

	hooks[0].hooknum = NF_INET_PRE_ROUTING;  		//use INET and not IP. IP is for userspace, INET is for kernel
	hooks[1].hooknum = NF_INET_POST_ROUTING;		//found this on linuxQuestions, a link is provided at the Doc(2)

	for (i = 0; i < 2; i++){
		hooks[i].pf = PF_INET;					//IPV4 packets
		hooks[i].priority = NF_IP_PRI_FIRST;	//set to highest priority over all other hook functions
		if (i == 0)
			hooks[i].hook = input_hook_func; 	//function to call
		else
			hooks[i].hook = output_hook_func;
		ret = nf_register_hook(&(hooks[i]));	//the return value. found that at ref (3) at the Doc.
		if (ret != 0) {
			return -1;
		}
	}
	firewall_activated = 1;
	return 0;
}

int close_hooks(void){
	printk(KERN_INFO "deactivating firewall");
	int i = 0;
	/* unregister the functions. found this also at link (1) at the Doc.*/
	for (i = 0; i < 2; i++)
		nf_unregister_hook(&(hooks[i]));
	firewall_activated = 0;
	return 0;
}

/* Every .c file requiers this. */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tzur Elyiahu");