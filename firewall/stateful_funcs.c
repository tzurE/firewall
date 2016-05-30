#include "stateful_funcs.h"

int num_of_conns;
connection_node *conn_tab_head = NULL;
connection_node *conn_tab_tail=NULL;


int update_syn_sent(rule_t packet, struct tcphdr* tcphd, connection_node *curr_conn){
	if (tcphd->ack){
		curr_conn->conn.protocol=tcp_ESTABLISHED;
		if(curr_conn->conn.type == FTP_HANDSHAKE){
			curr_conn->conn.protocol=tcp_ESTABLISHED;
			curr_conn->conn.type = FTP_ESTABLISHED;
		}
		else if (curr_conn->conn.type = HTTP_HANDSHAKE){
			curr_conn->conn.protocol=tcp_ESTABLISHED;
			curr_conn->conn.type = HTTP_ESTABLISHED;
		}
	}
	else // why is the ack off? fishy. drop it.
		return -1;
	return 1;
}

int update_syn_ack_sent(rule_t packet, struct tcphdr* tcphd, connection_node *curr_conn){
	if (tcphd->ack && tcphd->seq)
		curr_conn->conn.protocol=tcp_ESTABLISHED;
		if(curr_conn->conn.type == FTP_HANDSHAKE){
			curr_conn->conn.protocol=tcp_ESTABLISHED;
			curr_conn->conn.type = FTP_ESTABLISHED;
		}
		else if (curr_conn->conn.type = HTTP_HANDSHAKE){
			curr_conn->conn.protocol=tcp_ESTABLISHED;
			curr_conn->conn.type = HTTP_ESTABLISHED;
		}
	else
		return -1;
	return 1;
}

int update_connection(rule_t packet, struct tcphdr* tcphd, connection_node *curr_conn, connection_node *prev_conn){
	switch(curr_conn->conn.protocol){
		break;
		case tcp_SYN_SENT_WAIT_SYN_ACK:
			return update_syn_sent(packet, tcphd, curr_conn);

		break;
		case tcp_SYN_ACK_SENT_WAIT_ACK:
			return update_syn_ack_sent(packet, tcphd, curr_conn);

		break;
		case tcp_ESTABLISHED:

		
		break;
		case tcp_END:

		break;
	}
	return 1;
}

int create_new_connection(rule_t packet, int ack_state, int syn_state){
	connection *new_conn = NULL;
	struct timeval time_stamp;
	unsigned long time_var;
	connection_node *new_conn_node = kmalloc(sizeof(connection_node), GFP_ATOMIC);
	printk("enter create new connection\n");
	if (new_conn_node == NULL){
		(KERN_INFO "Error: could not allocate memory for new connection on the table\n");
		return 0;
	}
	do_gettimeofday(&time_stamp);
	if (conn_tab_tail == NULL){
		// list is empty
		conn_tab_tail = new_conn_node;

		//setting the head
		conn_tab_head = conn_tab_tail;
	}
	else {
		conn_tab_tail->next = new_conn_node;
		conn_tab_tail = new_conn_node;
	}

	new_conn = &conn_tab_tail->conn;
	new_conn->src_ip	= packet.src_ip;
	new_conn->dst_ip	= packet.dst_ip;
	new_conn->src_port	= packet.src_port;
	new_conn->dst_port	= packet.dst_port;
	time_var = time_stamp.tv_sec;
	new_conn->timestamp = time_var;

	//this is a new connection, what type?
	if (ntohs(packet.dst_port) == 21){
		if(!ack_state && syn_state)
			new_conn->protocol=tcp_SYN_SENT_WAIT_SYN_ACK;
		if (ack_state && syn_state)
			new_conn->protocol=tcp_SYN_ACK_SENT_WAIT_ACK;
		new_conn->type = FTP_HANDSHAKE;
	}
	else if (ntohs(packet.dst_port) == 80){
		if(!ack_state && syn_state)
			new_conn->protocol=tcp_SYN_SENT_WAIT_SYN_ACK;
		if (ack_state && syn_state)
			new_conn->protocol=tcp_SYN_ACK_SENT_WAIT_ACK;
		new_conn->type = HTTP_HANDSHAKE;
	}
	num_of_conns++;

	printk("exiting create new connection\n");
	return 1;
}
	

/* Try and find a suitable connection for this new packet. */
int check_statful_inspection(rule_t packet, struct tcphdr *tcphd, unsigned int hooknum){
	struct timeval time_stamp;
	connection_node *curr_conn, *prev_conn;
	connection * conn;

	do_gettimeofday(&time_stamp);

	while (curr_conn != NULL){
		conn = &curr_conn->conn;

		//is this connection timedout?
		// I use this to clean up connections
		if ((time_stamp.tv_sec - conn->timestamp) > 25){
			printk("connection timedout, removing it.\n");
			if(prev_conn != NULL){
				prev_conn->next = curr_conn->next;
				kfree(curr_conn);
				curr_conn = prev_conn->next;
			}
			else {
				conn_tab_head=curr_conn->next;
				kfree(curr_conn);
				curr_conn = conn_tab_head;
			}

			num_of_conns--;
			continue;
		}
		//did we find a matching connection?
		if (conn->src_ip == packet.src_ip && conn->src_port == packet.src_port && conn->dst_ip == packet.dst_ip && conn->dst_port == packet.dst_port){
			return update_connection(packet, tcphd, curr_conn, prev_conn);
		}
		//opposite connection! probably syn ack
		else if (conn->src_ip == packet.dst_ip && conn->src_port == packet.dst_port && conn->dst_ip == packet.src_ip && conn->dst_port == packet.src_port){
			if (tcphd->ack && tcphd->syn && curr_conn->conn.protocol == tcp_SYN_SENT_WAIT_SYN_ACK){
				// 2 means this is an opposite connection with syn and ack, so we need to open a new connection for the other side
				//this is the only case we open a new connection!
				return 2;
			}
			continue;
		}
	}


	return 1;

}