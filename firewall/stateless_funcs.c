#include "stateless_funcs.h"

int num_rules = 0;

rule_t rules[50];

int check_rule_exists(rule_t packet, int hooknum){
	int i = 0;

	for(i=0; i < num_rules; i++){
		// printk("rule: %d\n", i);
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
			// printk("prot not any and not other!\n");
			// printk("%d\n", rules[i].protocol);
			// printk("%d\n", packet.protocol);
			if(rules[i].protocol == packet.protocol){
				// printk("protocol is equal to rule %d\n", i);
				//protocol equal. check all of the cases:
				if(packet.protocol == PROT_ICMP){
					insert_log(&packet, i, rules[i].action, hooknum);
					return rules[i].action;
				}
				if(packet.protocol == PROT_TCP){
					//if ACK is ANY or ACK aquals packet ack - move on!
					//if port=0 - ok. if ports are equal - ok. if port is above 1023 and rule port is 1023 - ok.
					if ((packet.src_port == rules[i].src_port) || ((rules[i].src_port == PORT_ABOVE_1023) && (ntohs(packet.src_port) > 1023)) || (rules[i].src_port == PORT_ANY)) {
						if ((packet.dst_port == rules[i].dst_port) || ((rules[i].dst_port == PORT_ABOVE_1023) && (ntohs(packet.dst_port) > 1023)) || (rules[i].dst_port == PORT_ANY)) {
							//we got a match!
							if(rules[i].ack == ACK_ANY || rules[i].ack == packet.ack){
								insert_log(&packet, i, rules[i].action, hooknum);
								return rules[i].action;
							}
						}
					}
					
				}
				if (packet.protocol == PROT_UDP){
					if ((packet.src_port == rules[i].src_port) || ((rules[i].src_port == PORT_ABOVE_1023) && (ntohs(packet.src_port) > 1023)) || (rules[i].src_port == PORT_ANY)) {
						if ((packet.dst_port == rules[i].dst_port) || ((rules[i].dst_port == PORT_ABOVE_1023) && (ntohs(packet.dst_port) > 1023)) || (rules[i].dst_port == PORT_ANY)) {
							//we got a match!
							insert_log(&packet, i, rules[i].action, hooknum);
							return rules[i].action;

						}
					}
				}
				
			}
			continue;

		}
		
		//protocol is ANY. no need to check ports.
		//so we passed everything, and found a rule!
		insert_log(&packet, i, rules[i].action, hooknum);
		return rules[i].action;
	}
	//we did not find any rule.
	//block it
	//TODO - add log!
	printk("No rule was found. Accept.\n");
	insert_log(&packet, REASON_NO_MATCHING_RULE, 1, hooknum);
	return NF_ACCEPT;
}
