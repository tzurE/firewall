#include "stateful_funcs.h"

int num_of_conns=0;
connection_node *conn_tab_head = NULL;
connection_node *conn_tab_tail=NULL;

//globals
int command_index = 0;
char command[900];


connection_node* find_opposite_connection(rule_t packet, struct tcphdr *tcphd){
	int i = 0;
	connection_node *curr_conn = NULL;
	connection *conn;
	curr_conn=conn_tab_head;
	while (i < num_of_conns && curr_conn != NULL){
		i++;
		conn = &curr_conn->conn;
		if (conn->src_ip == packet.dst_ip && conn->src_port == packet.dst_port && conn->dst_ip == packet.src_ip && conn->dst_port == packet.src_port){
			return curr_conn;
		}
		curr_conn = curr_conn->next;
	}
	return NULL;
}

int update_syn_sent(rule_t packet, struct tcphdr* tcphd, connection_node *curr_conn){
	connection *conn = &curr_conn->conn;
	if (tcphd->ack){
		conn->protocol=tcp_ESTABLISHED;
		if(conn->type == FTP_HANDSHAKE){
			conn->protocol=tcp_ESTABLISHED;
			conn->type = FTP_ESTABLISHED;
		}
		else if (conn->type == HTTP_HANDSHAKE){
			conn->protocol=tcp_ESTABLISHED;
			conn->type = HTTP_ESTABLISHED;
		}
	}
	else // why is the ack off? fishy. drop it.
		return -1;
	return 1;
}

int update_syn_ack_sent(rule_t packet, struct tcphdr* tcphd, connection_node *curr_conn){
	connection *conn = &curr_conn->conn;
	if (tcphd->ack && tcphd->seq)
		conn->protocol=tcp_ESTABLISHED;
		if(conn->type == FTP_HANDSHAKE){
			conn->protocol=tcp_ESTABLISHED;
			conn->type = FTP_ESTABLISHED;
		}
		else if (conn->type == HTTP_HANDSHAKE){
			conn->protocol=tcp_ESTABLISHED;
			conn->type = HTTP_ESTABLISHED;
		}
	else if (conn->type == TCP_GEN_HANDSHAKE){
		conn->type = TCP_GEN_ESTABLISHED;
		conn->protocol=tcp_ESTABLISHED;
	}
	else 
		return -1;
	return 1;
}

int update_ftp_connection(rule_t packet, struct tcphdr* tcphd, struct iphdr *iphd ,connection_node *curr_conn, unsigned char *tail){
	connection_node *new_conn, *opposite_conn, *new_conn2;
	char* user_data = (char *)((int)tcphd + (int)(tcphd->doff * 4));
	connection *conn = &curr_conn->conn;
	struct timeval time_stamp;
	unsigned long curr_time;
	unsigned char *it; //for iterating the data 
	int end_of_command = 0;
	int	ip1, ip2, ip3, ip4, port1, port2;


	// handle fragmatation. accumulate chars to a buffer as seen here: (this is how i get the idea)
	// http://stackoverflow.com/questions/29553990/print-tcp-packet-data
	for (it = user_data; it != tail; ++it) {
        char c = *(char *)it;

        command[command_index] = c;
        command_index++;

        if (c == '\0'){
        	end_of_command = 1;
        	command_index = 0;
        	break;
        }

        if (c == 0x0d)
        	end_of_command = 2;
        else if (c == 0x0a && end_of_command == 2){
        	end_of_command = 1;
        	command_index = 0;
        	break;
        }
        if (command_index == 899){
        	strcpy(command, "");
        	command_index = 0;
        	printk("illegal ftp command. dropping packet!");
        	return -3;
        }
	}
	if(end_of_command == 0){
		printk("command not ended!\n");
		// 
		return 1;
	}

	do_gettimeofday(&time_stamp);
	curr_time = time_stamp.tv_sec;
	printk("type:%u ", conn->type);
	printk("command%s \n", command);
	if (conn->type == FTP_ESTABLISHED){
	// 230 means user is connected, as stated here - https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes
		if (strnicmp(command, "230", 3) == 0){	
			printk("FTP connected\n");
			conn->type = FTP_CONNECTED;
			opposite_conn = find_opposite_connection(packet, tcphd);
			opposite_conn->conn.type = FTP_CONNECTED;
		}
		else if (strnicmp(command, "QUIT", 4) == 0) {
			conn->type = FTP_END;
			conn->protocol = tcp_END;
		}
	}
	else if(conn->type == FTP_CONNECTED) {

		//start buffering text
		if (strnicmp(command, "PORT", 4) == 0){

			new_conn = create_new_connection(packet, iphd, 0, 0);

			sscanf(command, "PORT %d,%d,%d,%d,%d,%d", &ip1, &ip2, &ip3, &ip4, &port1, &port2);
			// as seen in lecture
			new_conn->conn.src_ip 	= ntohl((ip1<<24) + (ip2<<16) + (ip3<<8) + ip4);
			new_conn->conn.src_port = htons((port1 * 256) + port2);
			new_conn->conn.dst_port = htons(20);
			new_conn->conn.protocol = tcp_ESTABLISHED;
			new_conn->conn.type = FTP_TRANSFER;

			//create the opposite connection
			new_conn2 = create_new_connection(packet, iphd, 0, 0);

			sscanf(command, "PORT %d,%d,%d,%d,%d,%d", &ip1, &ip2, &ip3, &ip4, &port1, &port2);
			// as seen in lecture
			new_conn2->conn.src_ip = new_conn->conn.dst_ip;
			new_conn2->conn.dst_ip 	= ntohl((ip1<<24) + (ip2<<16) + (ip3<<8) + ip4);
			new_conn2->conn.dst_port = htons((port1 * 256) + port2);
			new_conn2->conn.src_port = htons(20);
			new_conn2->conn.protocol = tcp_ESTABLISHED;
			new_conn2->conn.type = FTP_TRANSFER;

		}
		else if (!strnicmp(command, "QUIT", 4)) {
			conn->type = FTP_END;
			conn->protocol = tcp_END;
		}
	}
	else if (conn->type == FTP_TRANSFER){
		if (tcphd->fin) {
			conn->type = FTP_END;
			conn->protocol=tcp_END;
		}
	}
	else if (conn->type == FTP_END){
		if (!tcphd->fin){
			strcpy(command, "");
			return -1;
		}
	}

	
	memset(&command[0], 0, sizeof(command));
	conn->timestamp = curr_time;
	return 1;

} 

int update_http_connection(rule_t packet, struct tcphdr* tcphd, struct iphdr *iphd ,connection_node *curr_conn, unsigned char *tail) {

	return 1;

}

int update_gen_connection(rule_t packet, struct tcphdr* tcphd, connection_node *curr_conn){

	return 1;

}

int update_connection(rule_t packet, struct tcphdr* tcphd,struct iphdr *iphd ,connection_node *curr_conn, unsigned char *tail){
	switch(curr_conn->conn.protocol){
		break;
		case tcp_SYN_SENT_WAIT_SYN_ACK:
			return update_syn_sent(packet, tcphd, curr_conn);

			break;
		case tcp_SYN_ACK_SENT_WAIT_ACK:
			return update_syn_ack_sent(packet, tcphd, curr_conn);

			break;
		case tcp_ESTABLISHED:
			if(curr_conn->conn.type == FTP_ESTABLISHED || curr_conn->conn.type == FTP_CONNECTED || curr_conn->conn.type == FTP_TRANSFER || curr_conn->conn.type == FTP_END){
				return update_ftp_connection(packet, tcphd, iphd ,curr_conn, tail);
			}
			else if(curr_conn->conn.type == HTTP_ESTABLISHED || curr_conn->conn.type == HTTP_CONNECTED || curr_conn->conn.type == HTTP_END){
				return update_http_connection(packet, tcphd, iphd ,curr_conn, tail);
			}
			else {
				update_gen_connection(packet, tcphd ,curr_conn);
			}

		
			break;
		case tcp_END:

			break;
	}
	return 1;
}
int close_connection(rule_t packet, struct tcphdr* tcphd, connection_node *curr_conn){
	connection *conn = &curr_conn->conn;

	if(conn->type == FTP_ESTABLISHED || conn->type == FTP_CONNECTED || conn->type == FTP_TRANSFER || conn->type == FTP_HANDSHAKE ){
		conn->type = FTP_END;
		conn->protocol = tcp_END;

	}
	else if(conn->type == HTTP_ESTABLISHED || conn->type == HTTP_CONNECTED || conn->type == HTTP_HANDSHAKE){
		conn->type = HTTP_END;
		conn->protocol = tcp_END;

	}
	else if (conn->type == TCP_GEN_ESTABLISHED ){
		conn->type = TCP_GEN_END;
		conn->protocol = tcp_END;
	}
	return 1;


}

connection_node* create_new_connection(rule_t packet, struct iphdr *iphd ,int ack_state, int syn_state){
	connection *new_conn = NULL;
	struct timeval time_stamp;
	unsigned long time_var;
	connection_node *new_conn_node = kmalloc(sizeof(connection_node), GFP_ATOMIC);
	
	if (new_conn_node == NULL){
		(KERN_INFO "Error: could not allocate memory for new connection on the table\n");
		return 0;
	}
	do_gettimeofday(&time_stamp);
	new_conn_node->next = conn_tab_head; // Add to dynamic table
	conn_tab_head = new_conn_node;

	new_conn = &new_conn_node->conn;
	new_conn->src_ip	= packet.src_ip;
	new_conn->dst_ip	= packet.dst_ip;
	new_conn->src_port	= packet.src_port;
	new_conn->dst_port	= packet.dst_port;
	new_conn->id 		= iphd->id;
	new_conn->frag_off 	= iphd->frag_off;
	time_var = time_stamp.tv_sec;
	new_conn->timestamp = time_var;

	//this is a new connection, what type?
	if (ntohs(packet.dst_port) == 21 || ntohs(packet.src_port) == 21){
		if(!ack_state && syn_state)
			new_conn->protocol=tcp_SYN_SENT_WAIT_SYN_ACK;
		if (ack_state && syn_state)
			new_conn->protocol=tcp_SYN_ACK_SENT_WAIT_ACK;
		new_conn->type = FTP_HANDSHAKE;
	}
	else if (ntohs(packet.dst_port) == 80 || ntohs(packet.src_port) == 80){
		if(!ack_state && syn_state)
			new_conn->protocol=tcp_SYN_SENT_WAIT_SYN_ACK;
		if (ack_state && syn_state)
			new_conn->protocol=tcp_SYN_ACK_SENT_WAIT_ACK;
		new_conn->type = HTTP_HANDSHAKE;
	}
	else {
		if(!ack_state && syn_state)
			new_conn->protocol=tcp_SYN_SENT_WAIT_SYN_ACK;
		if (ack_state && syn_state)
			new_conn->protocol=tcp_SYN_ACK_SENT_WAIT_ACK;
		new_conn->type = TCP_GEN_HANDSHAKE;
	}
	num_of_conns++;

	
	return new_conn_node;
}

int is_connection_exists(rule_t packet, struct tcphdr *tcphd){
	connection_node *curr_conn=NULL;
	connection *conn;
	int i = 0;
	curr_conn=conn_tab_head;
	while (i < num_of_conns && curr_conn != NULL){
		i++;
		conn = &curr_conn->conn; 
		if (conn->src_ip == packet.src_ip && conn->src_port == packet.src_port && conn->dst_ip == packet.dst_ip && conn->dst_port == packet.dst_port){
			return 1;
		}
		curr_conn = curr_conn->next;

	}
	return 0;

}
	

/* Try and find a suitable connection for this new packet. */
int check_statful_inspection(rule_t packet, struct tcphdr *tcphd, struct iphdr *iphd ,unsigned int hooknum, unsigned char *tail){
	struct timeval time_stamp;
	connection_node *curr_conn=NULL, *prev_conn=NULL;
	connection *conn;
	int i = 0;

	do_gettimeofday(&time_stamp);
	curr_conn=conn_tab_head;
	while (i < num_of_conns && curr_conn != NULL){
		i++;
		conn = &curr_conn->conn;

		//is this connection timedout?
		// I use this to clean up connections
		if ((time_stamp.tv_sec - conn->timestamp) > 25 && (conn->protocol != tcp_ESTABLISHED || conn->protocol == tcp_END || conn->type == FTP_TRANSFER || conn->timestamp > 25*20)){
			printk("connection timedout, removing it.\n");
			num_of_conns--;
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
			continue;
		}
		//did we find a matching connection?
		if (conn->src_ip == packet.src_ip && conn->src_port == packet.src_port && conn->dst_ip == packet.dst_ip && conn->dst_port == packet.dst_port){
			// printk("%u, %u, %u, %u\n",conn->id, iphd->id, conn->frag_off, iphd->frag_off);
			if (conn->id == iphd->id && conn->frag_off == iphd->frag_off){
				//different hook, same packet! ignore
				return 3;
			}
			else if (tcphd->fin && conn->type != FTP_TRANSFER){
				close_connection(packet, tcphd, curr_conn);
			}
			else 
				return update_connection(packet, tcphd, iphd ,curr_conn, tail);
		}
		// seperate this. if No connection - then look for opposite one.
		//opposite connection! probably syn ack
		else if (conn->src_ip == packet.dst_ip && conn->src_port == packet.dst_port && conn->dst_ip == packet.src_ip && conn->dst_port == packet.src_port){
			if (tcphd->ack && tcphd->syn && curr_conn->conn.protocol == tcp_SYN_SENT_WAIT_SYN_ACK){
				// 2 means this is an opposite connection with syn and ack, so we need to open a new connection for the other side
				//this is the only case we open a new connection!
				return 2;
			}
			//do nothing

		}
		prev_conn = curr_conn;
		curr_conn = curr_conn->next;
		
	}


	return 1;

}