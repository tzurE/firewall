#include "stateless_funcs.h"

int num_rules = 0;

rule_t rules[50];

int check_rule_exists(rule_t packet, int hooknum){
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



	return NF_ACCEPT;
}
