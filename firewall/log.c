#include "log.h"

int log_size_var = 0;
log_node *log_list = NULL;

int insert_log(rule_t *packet, rule_t *rule, reason_t reason, int action, int hooknum){

	log_row_t *new_log_entry;
	log_node *curr;
	log_node *new_node;
	struct timeval insert_time;

	//http://www.makelinux.net/books/lkd2/ch11lev1sec4
	//want to use the atomic allocation - no sleep for this thread.
	new_node = kmalloc(sizeof(log_node), GFP_ATOMIC);
	if (new_node == NULL){
		printk(KERN_INFO "Error alocating log node, cannot log packet info\n");
		return -1;
	}

	//point to the log entry of the new node, and populate it.
	//we could just use the new node, but this is clearer.
	new_log_entry = &new_node->log_entry;

	//populate the entry
	do_gettimeofday(&insert_time);
	//timestamp with u32 flag
	new_log_entry->timestamp = (u32)insert_time.tv_sec;
	new_log_entry->action = action;
	new_log_entry->reason=reason;
	new_log_entry->hooknum=hooknum;

	//populate entry using data from packet
	new_log_entry->protocol=packet->protocol;
	new_log_entry->src_ip=packet->src_ip;
	new_log_entry->dst_ip=packet->dst_ip;
	new_log_entry->src_port=packet->src_port;
	new_log_entry->dst_port=packet->dst_port;
	new_log_entry->count=1;

	//treverse the log
	curr = log_list;
	while (curr != NULL){

		if(curr->log_entry.reason == reason && curr->log_entry.protocol == packet->protocol &&
			curr->log_entry.src_ip == packet->src_ip && curr->log_entry.dst_ip == packet->dst_ip &&
			curr->log_entry.src_port == packet->src_port && curr->log_entry.dst_port == packet->dst_port &&
			curr->log_entry.action == action) {


			curr->log_entry.timestamp = (u32)insert_time.tv_sec;
			curr->log_entry.count++;
			//we don't need the new node, free it
			kfree(new_node);
			//success
			return 1;
		}
		//go forward on list
		curr=(curr->next);
		continue;
	}
	//didn't find a log entry. insert it
	new_node->next=log_list;
	log_list = new_node;
	log_size_var++;


}
