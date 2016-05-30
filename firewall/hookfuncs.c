#include "hookfuncs.h"

struct nf_hook_ops hooks[3];
extern int firewall_activated;
int stateful_inspection_res;

int parse_packet(struct sk_buff *skb, const struct net_device *net_d, unsigned int hooknum, int dir){
	rule_t packet;
	struct iphdr *iphd;
	struct tcphdr *tcphd;
	struct udphdr *udphd;
	int create_conn_res;

	iphd = ip_hdr(skb);
	// tcphd = (struct tcphdr *)(skb_transport_header(skb)+20);
	// udphd = (struct udphdr *)(skb_transport_header(skb));

	if (skb_transport_header(skb) == (unsigned char *)iphd){
		// printk("in if\n");
		//http://stackoverflow.com/questions/29656012/netfilter-like-kernel-module-to-get-source-and-destination-address
		tcphd = ((unsigned char *)iphd + (iphd->ihl * 4)); /* Skip IP hdr */
		udphd = ((unsigned char *)iphd + (iphd->ihl * 4)); /* Skip IP hdr */

	}
	else {
		// printk("in else\n");
		tcphd = (struct tcphdr *)(skb_transport_header(skb));
		udphd = (struct udphdr *)(skb_transport_header(skb));
	}

	//get ips
	packet.src_ip = iphd->saddr;
	packet.dst_ip = iphd->daddr;
	//what direction are you going?
	//first we check if it goes into eth1 or eth2, if so we give direction accordingly
	if (net_d->name != NULL && ((strcmp(net_d->name, IN_NET_DEVICE_NAME)==0) || (strcmp(net_d->name, OUT_NET_DEVICE_NAME)==0))){
		if (dir == 20){ //in pre hook
			//if you're from eth1 - direction is OUT. if you're from eth2 direction is - IN
			if (strcmp(net_d->name, IN_NET_DEVICE_NAME) == 0)
				packet.direction=DIRECTION_OUT;
			else
				packet.direction=DIRECTION_IN;
		}
		else { //in post hook
			//if you're going to eth1 - IN. if youre going to eth2 - OUT.
			if (strcmp(net_d->name, IN_NET_DEVICE_NAME) == 0)
				packet.direction=DIRECTION_IN;
			else
				packet.direction=DIRECTION_OUT;

		}
	}
	else { //it's not from eth1 or eth2. we still monitor it
		//I chose to give it the direction - 'any', becuase it is not going to eth1 or eth2
		packet.direction=DIRECTION_ANY;
	}
	//assign protocol
	packet.protocol = iphd->protocol;
	// in case firewall is off - no need to check rules. so accept all!
	if (firewall_activated == 0){
		//need to log here
		insert_log(&packet, REASON_FW_INACTIVE, 1, hooknum);
		return NF_ACCEPT;
	}

	if (packet.protocol == PROT_UDP){
		printk("prot:UDP, hooknum: %d, src: %d, dst: %d\n", packet.src_ip, packet.dst_ip);
		packet.src_port = udphd->source;
		packet.dst_port = udphd->dest;
	}
	// if we recognized a TCP packet - we transfer it to the stateful part. 
	else if (packet.protocol == PROT_TCP){
		printk("prot:TCP, hooknum: %d direction: %d, src: %d, dst: %d\n", hooknum ,packet.direction, packet.src_ip, packet.dst_ip);
		packet.src_port = tcphd->source;
		packet.dst_port = tcphd->dest;
		if (tcphd->ack)
			packet.ack = ACK_YES;
		else 
			packet.ack = ACK_NO;

		//if it's TCP, we can handel christmas
		if (tcphd->psh && tcphd->urg && tcphd->fin){
			printk("XMAS packet\n");
			insert_log(&packet, REASON_XMAS_PACKET, 0, hooknum);
			return NF_DROP;
		}

		// now to transfer it to a seperate check against the static table
		// if we found a static rule match - we'll continue with the conn tab.
		//ack is on, meaning this is a packet of existing connection
		if (tcphd->ack){
			// is there a connection for you? if so, update it.
			stateful_inspection_res = check_statful_inspection(packet, tcphd, hooknum);
			printk("ack on\n");
			if (stateful_inspection_res == 1){
				//we found a connection!
				printk("This is a known connection, conn table updated\n");
				return NF_ACCEPT;
			}
			if (stateful_inspection_res == 2){
				//2 means we found an opposite side connection in the sent syn state
				//if ack and syn on - this is a return answer to an already opened connection
				printk("ack on, syn on. creating connection:\n");
				create_new_connection(packet, 1, 1);
				return NF_ACCEPT;
				// no known connection found, and syn is off. 
				printk("Error: there is an opposite conn in syn-ack state but syn is off\n");
				return NF_DROP;
			}
			else if (stateful_inspection_res == -1){
				//result is -1, drop!
				return NF_DROP;
			}
		}
		else {
			printk("ack off, creating new connection\n");
			// ack is off - create new connection.
			// Check if the connection is ok with the static rules
			if (check_rule_exists(packet, hooknum) == NF_ACCEPT){
				if (create_new_connection(packet, 0, 1) == 1)	
					return NF_ACCEPT;
				else {
					printk(KERN_ERR "Error creating new connection on connection table, Dropping packet\n");
					return NF_DROP;
				}
			}
			else {
				//no need to write in log, already happend.
				return NF_DROP;
			}
			
		}

	}
	else if (packet.protocol == PROT_ANY){
		packet.src_port = PORT_ANY;
		packet.dst_port = PORT_ANY;
	}

	return check_rule_exists(packet, hooknum);
}

unsigned int input_hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
  return parse_packet(skb, in, hooknum, 20);
}

unsigned int output_hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
  return parse_packet(skb, out, hooknum, 0);
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

