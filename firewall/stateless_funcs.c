#include "stateless_funcs.h"

int num_rules = 0;

rule_t rules[50];

int check_rule_exists(rule_t packet, int hooknum){
	int i = 0;
	// char source[16]="";
	// printk(KERN_INFO "src:");
	// snprintf(source, 16, "%pI4", &packet.src_ip);
	// printk(source);
	// char source2[16] = "";
	// snprintf(source2, 16, "%lu", &packet.src_ip);
	// printk(source2);

	// printk(KERN_INFO "direction: ");
	// printk("%d",packet.direction);
	// printk("prot: %d\n", packet.protocol);
	// printk("ports: %d, %d \n", packet.src_port, packet.dst_port);
	// printk(KERN_INFO "\n");

	for(i=0; i < num_rules; i++){

		//check direction. if no match - move to the next rule!
		if(rules[i].direction != DIRECTION_ANY && rules[i].direction != packet.direction){
			//not a match. next rule.
			continue;
		}
		//had a match in direction. check ip's.
		if(rules[i].src_ip != 0){ //if ip==0, it means any address, and we passed.
			if ((rules[i].src_ip & rules[i].src_prefix_mask) != (packet.src_ip & rules[i].src_prefix_mask)){
				//no match. next rule.
				continue;
			}
		}
		//src ip match. check dst.
		if(rules[i].dst_ip != 0){ //if ip==0, it means any address, and we passed.
			if ((rules[i].dst_ip & rules[i].dst_prefix_mask) != (packet.dst_ip & rules[i].dst_prefix_mask)){
				//no match. next rule.
				continue;
			}
		}
		//dst ip match. check protocol:
		//if the rule is "ANY" or OTHER, we're ok and should move on.
		if (rules[i].protocol != PROT_ANY && rules[i].protocol != PROT_OTHER){
			if(rules[i].protocol != packet.protocol){
				//not a match.
				continue;
			}
			//protocol equal. check all of the cases:
			if(packet.protocol == PROT_ICMP){
				//TODO - Add log!
				printk(KERN_INFO "rule:%s, action: %d\n", rules[i].rule_name, rules[i].action);
				return rules[i].action;
			}
			//if port=0 - ok. if ports are equal - ok. if port is above 1023 and rule port is 1023 - ok.
			if ((packet.src_port == rules[i].src_port) || ((rules[i].src_port = 1023) && (packet.src_port > 1023)) || (rules[i].src_port == 0)) {
				if ((packet.dst_port == rules[i].dst_port) || ((rules[i].dst_port = 1023) && (packet.dst_port > 1023)) || (rules[i].dst_port == 0)) {
					//we got a match!
					//now check for UDP or TCP
					if(packet.protocol == PROT_TCP){
						//if ACK is ANY or ACK aquals packet ack - found a rule!
						if(rules[i].ack == ACK_ANY || rules[i].ack == packet.ack){
							printk(KERN_INFO "TCP rule %s, %d\n", rules[i].rule_name, rules[i].action);
							return rules[i].action;
						}
					}
					else if (packet.protocol == PROT_UDP){
						printk(KERN_INFO "UDP rule %s, %d\n", rules[i].rule_name, rules[i].action);
						return rules[i].action;
					}

				}
				//the dst ports didn't match - next rule
				continue;
			}
			//the src ports didnt match - next rule.
			continue;
		}
		//protocol is ANY. check ports
		if ((packet.src_port == rules[i].src_port) || ((rules[i].src_port = 1023) && (packet.src_port > 1023)) || (rules[i].src_port == 0)) {
			if ((packet.dst_port == rules[i].dst_port) || ((rules[i].dst_port = 1023) && (packet.dst_port > 1023)) || (rules[i].dst_port == 0)) {
				//match
				printk(KERN_INFO "rule: %s, %d\n", rules[i].rule_name, rules[i].action);
				return rules[i].action;
			}
		}
	}
	//we did not find any rule.
	//block it
	//TODO - add log!
	printk("No rule was found. blocked.");
	return NF_DROP;
}
