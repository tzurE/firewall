#include "hookfuncs.h"

struct nf_hook_ops hooks[3];
extern int firewall_activated;
int stateful_inspection_res;

int parse_packet(struct sk_buff *skb, const struct net_device *net_d, unsigned int hooknum, int dir){
	rule_t packet;
	struct iphdr *iphd;
	struct tcphdr *tcphd;
	struct udphdr *udphd;
	unsigned char *tail;

	iphd = ip_hdr(skb);
	// tcphd = (struct tcphdr *)(skb_transport_header(skb)+20);
	// udphd = (struct udphdr *)(skb_transport_header(skb));

	if (skb_transport_header(skb) == (unsigned char *)iphd){
		// printk("in if\n");
		//http://stackoverflow.com/questions/29656012/netfilter-like-kernel-module-to-get-source-and-destination-address
		tcphd = (struct tcphdr *)((unsigned char *)iphd + (iphd->ihl * 4)); /* Skip IP hdr */
		udphd = (struct udphdr *)((unsigned char *)iphd + (iphd->ihl * 4)); /* Skip IP hdr */

	}
	else {
		// printk("in else\n");
		tcphd = (struct tcphdr *)(skb_transport_header(skb));
		udphd = (struct udphdr *)(skb_transport_header(skb));
	}
	// end of packet, for parsing
	tail = skb_tail_pointer(skb);

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
		// printk("prot:UDP, hooknum: %d, src: %d, dst: %d\n", packet.src_ip, packet.dst_ip);
		packet.src_port = udphd->source;
		packet.dst_port = udphd->dest;
	}
	// if we recognized a TCP packet - we transfer it to the stateful part. 
	else if (packet.protocol == PROT_TCP){
		packet.src_port = tcphd->source;
		packet.dst_port = tcphd->dest;
		printk("prot:TCP, hooknum: %d direction: %d, src: %d, dst: %d, s_p:%u , d_p:%u \n", hooknum ,packet.direction, packet.src_ip, packet.dst_ip, ntohs(packet.src_port), ntohs(packet.dst_port));
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
		stateful_inspection_res = check_statful_inspection(packet, tcphd, iphd ,hooknum, tail, skb);
		printk("res = %d\n", stateful_inspection_res);
		// now to transfer it to a seperate check against the static table
		// if we found a static rule match - we'll continue with the conn tab.
		//ack is on, meaning this is a packet of existing connection. no need to go through static rules!
		if (tcphd->ack){
			// is there a connection for you? if so, update it.
			// printk("ack on\n");
			if (stateful_inspection_res == 1){
				//we found a connection!
				// printk("This is a known connection, conn table updated\n");
				return NF_ACCEPT;
			}
			if (stateful_inspection_res == 2 && !is_connection_exists(packet, tcphd)){
				//2 means we found an opposite side connection in the sent syn state
				//if ack and syn on - this is a return answer to an already opened connection, and the connection does not exists.
				// printk("ack on, syn on. creating connection:\n");
				create_new_connection(packet, iphd ,1, 1);
				return NF_ACCEPT;
			}
			if (stateful_inspection_res == -1){
				//result is -1, drop!
				insert_log(&packet, REASON_CONN_NOT_EXIST, 0, hooknum);
				return NF_DROP;
			}
			if (stateful_inspection_res == -3){
				insert_log(&packet, REASON_CONN_NOT_COMPLINT, 0, hooknum);
				return NF_DROP;
			}
		}
		else {
			// printk("ack off\n");
			// ack is off - create new connection.
			// Check if the connection is ok with the static rules
			//first just check is this connection exists - before opening. if it exists - do not open!
			if (stateful_inspection_res != 3 && (check_rule_exists(packet, hooknum) == NF_ACCEPT) && !is_connection_exists(packet, tcphd)){
				printk("Creating new connection\n");
				create_new_connection(packet, iphd ,0, 1);	
				return NF_ACCEPT;
				
			}
			else {
				//3 meaning this is a duplicate, 1 meaning this is an already exists connection with ack off (transfer opens them automaticly)
				if (stateful_inspection_res == 3 || stateful_inspection_res == 1)
					return NF_ACCEPT;
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

