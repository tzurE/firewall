#include "hookfuncs.h"
#include "fw.h"
#include "stateless_funcs.h"


/* index 1 is for the forward hook, index 2-3 is for input/output hooks
more on this at the Doc added */
struct nf_hook_ops hooks[3];
int cnt_blocked = 0, cnt_accepted = 0;
extern int firewall_activated;

int packet_get(struct sk_buff *skb, const struct net_device *net_d, unsigned int hooknum, int dir){
	rule_t packet;
	struct iphdr *iphd;
	struct tcphdr *tcphd;
	struct udphdr *udphd;

	iphd = ip_hdr(skb);
	//if dir = 20 then it's input. else it's 0 then it's output
	//as shown in class and in stackoverflow (documented)
	tcphd = (struct tcphdr *)(skb_transport_header(skb)+dir);
	udphd = (struct udphdr *)(skb_transport_header(skb));

	//get ips
	packet.src_ip = iphd->saddr;
	packet.dst_ip = iphd->daddr;
	//what direction are you going?
	if (net_d->name != NULL && ((strcmp(net_d->name, IN_NET_DEVICE_NAME)==0) || (strcmp(net_d->name, OUT_NET_DEVICE_NAME)==0))){
		if (dir == 20){ //in pre hook
			printk("hook in\n");
			if (strcmp(net_d->name, IN_NET_DEVICE_NAME) == 0)
				packet.direction=DIRECTION_OUT;
			else
				packet.direction=DIRECTION_IN;
		}
		else { //in post hook
			printk("hook out\n");
			if (strcmp(net_d->name, IN_NET_DEVICE_NAME) == 0)
				packet.direction=DIRECTION_IN;
			else
				packet.direction=DIRECTION_OUT;

		}
	}
	else { //it didn't came from any monitored net device, we'll allow it
		
		return NF_ACCEPT;
	}

	//assign protocol
	packet.protocol = iphd->protocol;
	//return accept but write in log first!
	if (firewall_activated == 0){
		char source[16]="";
		//need to log here
		printk(KERN_INFO "packet passed, firewall is offline. src:");
		snprintf(source, 16, "%pI4", &packet.src_ip);
		printk(source);
		printk(KERN_INFO "\n");
		return NF_ACCEPT;
	}

	if (packet.protocol == PROT_UDP){
		packet.src_port = udphd->source;
		packet.dst_port = udphd->dest;
	}
	else if (packet.protocol == PROT_TCP){
		packet.src_port = tcphd->source;
		packet.dst_port = tcphd->dest;
		if (tcphd->ack)
			packet.ack = ACK_YES;
		else 
			packet.ack = ACK_NO;

		//if it's TCP, we can handel christmas
		if (tcphd->psh && tcphd->urg && tcphd->fin){
			printk("XMAS");
			return NF_DROP;
		}
	}
	else if (packet.protocol == PROT_ANY){
		packet.src_port = PORT_ANY;
		packet.dst_port = PORT_ANY;
	}

	return check_rule_exists(packet, hooknum);
}

unsigned int input_hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
  return packet_get(skb, in, hooknum, 20);
}

unsigned int output_hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
  return packet_get(skb, out, hooknum, 0);
}


int start_hooks(void){
	int i = 0, ret;
	printk(KERN_INFO "Activating firewall\n");

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
	int i = 0;
	printk(KERN_INFO "deactivating firewall");
	/* unregister the functions. found this also at link (1) at the Doc.*/
	for (i = 0; i < 2; i++)
		nf_unregister_hook(&(hooks[i]));
	firewall_activated = 0;
	return 0;
}

/* Every .c file requiers this. */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tzur Elyiahu");

