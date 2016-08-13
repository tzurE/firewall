#include "stateful_funcs.h"


//externs
int num_of_conns=0;
connection_node *conn_tab_head = NULL;
connection_node *conn_tab_tail=NULL;
char *hosts_list = NULL;
int size_of_hosts;



//globals
int ftp_command_index = 0;
int http_command_index = 0;

char ftp_command[900];
char *http_command=NULL;
char http_command2[500]="";
char *smtp_command=NULL;
char smtp_command2[500]="";


connection_node* insert_new_connection(connection_node* curr_conn){
	curr_conn->next = conn_tab_head; // Add to dynamic table
	conn_tab_head = curr_conn;
	return curr_conn;
}

connection_node* create_new_connection_node(rule_t packet, struct iphdr *iphd ,int ack_state, int syn_state){
	connection *new_conn = NULL;
	struct timeval time_stamp;
	unsigned long time_var;
	connection_node *new_conn_node = kmalloc(sizeof(connection_node), GFP_ATOMIC);
	
	if (new_conn_node == NULL){
		printk(KERN_INFO "Error: could not allocate memory for new connection on the table\n");
		return 0;
	}
	do_gettimeofday(&time_stamp);

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
	else if (ntohs(packet.dst_port) == 25 || ntohs(packet.src_port) == 25){
		if(!ack_state && syn_state)
			new_conn->protocol=tcp_SYN_SENT_WAIT_SYN_ACK;
		if (ack_state && syn_state)
			new_conn->protocol=tcp_SYN_ACK_SENT_WAIT_ACK;
		new_conn->type = SMTP_HANDSHAKE;
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


connection_node* create_new_connection(rule_t packet, struct iphdr *iphd, int ack_state, int syn_state){
	return insert_new_connection(create_new_connection_node(packet, iphd, ack_state, syn_state));
}


int is_connection_exists(rule_t packet, struct tcphdr *tcphd){
	connection_node *curr_conn=NULL;
	connection *conn;
	curr_conn=conn_tab_head;
	while ( curr_conn != NULL){
		conn = &curr_conn->conn; 
		if (conn->src_ip == packet.src_ip && conn->src_port == packet.src_port && conn->dst_ip == packet.dst_ip && conn->dst_port == packet.dst_port){
			return 1;
		}
		curr_conn = curr_conn->next;

	}
	return 0;

}

int is_connection_exists_no_packet(connection_node * new_conn){
	connection_node *curr_conn=NULL;
	connection *conn;
	curr_conn=conn_tab_head;
	while (curr_conn != NULL){
		conn = &curr_conn->conn; 
		if (conn->src_ip == new_conn->conn.src_ip && conn->src_port == new_conn->conn.src_port && conn->dst_ip == new_conn->conn.dst_ip && conn->dst_port == new_conn->conn.dst_port){
			return 1;
		}
		curr_conn = curr_conn->next;

	}
	return 0;

}


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
		else if (conn->type == SMTP_HANDSHAKE){
			conn->protocol=tcp_ESTABLISHED;
			conn->type = SMTP_START;
		}
	}
	else { // why is the ack off? fishy. drop it.
		// printk("dropping\n");
		return -1;
	}
	return 1;
}

int update_syn_ack_sent(rule_t packet, struct tcphdr* tcphd, connection_node *curr_conn){
	connection *conn = &curr_conn->conn;
	if (tcphd->ack && tcphd->seq){
		conn->protocol=tcp_ESTABLISHED;
		if(conn->type == FTP_HANDSHAKE){
			conn->protocol=tcp_ESTABLISHED;
			conn->type = FTP_ESTABLISHED;
		}
		else if (conn->type == HTTP_HANDSHAKE){
			conn->protocol=tcp_ESTABLISHED;
			conn->type = HTTP_ESTABLISHED;
		}
		else if (conn->type == SMTP_HANDSHAKE){
			conn->protocol=tcp_ESTABLISHED;
			conn->type = SMTP_START;
		}
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

        ftp_command[ftp_command_index] = c;
        ftp_command_index++;

        if (c == '\0'){
        	end_of_command = 1;
        	ftp_command_index = 0;
        	break;
        }

        if (c == 0x0d)
        	end_of_command = 2;
        else if (c == 0x0a && end_of_command == 2){
        	end_of_command = 1;
        	ftp_command_index = 0;
        	break;
        }
        if (ftp_command_index == 899){
        	strcpy(ftp_command, "");
        	ftp_command_index = 0;
        	printk("illegal ftp command. dropping packet!");
        	return -3;
        }
	}
	if(end_of_command == 0){
		// command not ended, saving for next packet
		return 1;
	}

	do_gettimeofday(&time_stamp);
	curr_time = time_stamp.tv_sec;
	if (conn->type == FTP_ESTABLISHED){
	// 230 means user is connected, as stated here - https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes
		if (strnicmp(ftp_command, "230", 3) == 0){	
			conn->type = FTP_CONNECTED;
			opposite_conn = find_opposite_connection(packet, tcphd);
			opposite_conn->conn.type = FTP_CONNECTED;
		}
		else if (strnicmp(ftp_command, "QUIT", 4) == 0) {
			conn->type = FTP_END;
			conn->protocol = tcp_END;
		}
	}
	else if(conn->type == FTP_CONNECTED) {

		//start buffering text
		if (strnicmp(ftp_command, "PORT", 4) == 0){

			new_conn = create_new_connection_node(packet, iphd, 0, 0);

			sscanf(ftp_command, "PORT %d,%d,%d,%d,%d,%d", &ip1, &ip2, &ip3, &ip4, &port1, &port2);
			// as seen in lecture
			new_conn->conn.src_ip 	= ntohl((ip1<<24) + (ip2<<16) + (ip3<<8) + ip4);
			new_conn->conn.src_port = htons((port1 * 256) + port2);
			new_conn->conn.dst_port = htons(20);
			new_conn->conn.protocol = tcp_ESTABLISHED;
			new_conn->conn.type = FTP_TRANSFER;
			if (!is_connection_exists_no_packet(new_conn))
				insert_new_connection(new_conn);
			else
				kfree(new_conn);

			//create the opposite connection
			new_conn2 = create_new_connection_node(packet, iphd, 0, 0);

			sscanf(ftp_command, "PORT %d,%d,%d,%d,%d,%d", &ip1, &ip2, &ip3, &ip4, &port1, &port2);
			// as seen in lecture
			new_conn2->conn.src_ip = new_conn->conn.dst_ip;
			new_conn2->conn.dst_ip 	= ntohl((ip1<<24) + (ip2<<16) + (ip3<<8) + ip4);
			new_conn2->conn.dst_port = htons((port1 * 256) + port2);
			new_conn2->conn.src_port = htons(20);
			new_conn2->conn.protocol = tcp_ESTABLISHED;
			new_conn2->conn.type = FTP_TRANSFER;

			if (!is_connection_exists_no_packet(new_conn2))
				insert_new_connection(new_conn2);
			else
				kfree(new_conn2);

		}
		else if (strnicmp(ftp_command, "QUIT", 4) == 0) {
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
			strcpy(ftp_command, "");
			return -1;
		}
	}

	
	memset(&ftp_command[0], 0, sizeof(ftp_command));
	conn->timestamp = curr_time;
	return 1;

} 

int find_host_match(char* host_name){
	char* temp_hosts_list = kmalloc(size_of_hosts*sizeof(char), GFP_ATOMIC);
	char *host_line=NULL; 
	char* pointer_temp;

	if (hosts_list == NULL){
		kfree(temp_hosts_list);
		return 0;
	}
	strcpy(temp_hosts_list, hosts_list);
	pointer_temp = temp_hosts_list;
	host_line = strsep(&temp_hosts_list, "\n");
	while (temp_hosts_list != NULL){
		if (strcmp(host_line, host_name) == 0){
			printk("Host name is blocked. dropping packet\n");
			kfree(pointer_temp);
			return 1;
		}
		host_line = strsep(&temp_hosts_list, "\n");
	}
	kfree(pointer_temp);
	return 0;
}

int update_http_connection(rule_t packet, struct tcphdr* tcphd, struct iphdr *iphd ,connection_node *curr_conn, unsigned char *tail, struct sk_buff *skb) {
	connection *conn = &curr_conn->conn;
	struct timeval time_stamp;
	char host_name[200];
	unsigned long curr_time;
	int found_host = 0, i = 0, result = 1;
	int http_command_offset = iphd->ihl*4 + tcphd->doff*4; 
	int http_command_length = skb->len - http_command_offset;
	char *command_pointer;
	char *http_command3;
	char *http_command4;
	char *line = NULL;


	http_command =  kcalloc(http_command_length + 1,sizeof(char) , GFP_ATOMIC);
	skb_copy_bits(skb, http_command_offset , (void*)http_command, http_command_length);
	command_pointer = http_command;

	http_command4 = kcalloc(http_command_length + 1,sizeof(char) , GFP_ATOMIC);
	http_command3 = kcalloc(http_command_length + 1,sizeof(char) , GFP_ATOMIC);
	if (conn->type == HTTP_ESTABLISHED || conn->type == HTTP_CONNECTED || conn->type == HTTP_HANDSHAKE){
		if (strnicmp(http_command, "GET", 3) == 0 ){
			strcpy(http_command3, http_command);
			line = strsep(&http_command, "\n");
			conn->type = HTTP_CONNECTED;
			// search for host and compare it to the list we have
			while (http_command != NULL && !found_host){
				i++;
				if(strnicmp(line, "Host: ", 6) == 0){
					found_host = 1;
					strcpy(host_name, line + 6);
					//compare to the list
					if (find_host_match(host_name))
						result = -9;
					break;
				}
				else if (i > 80){
					printk("Get packet is not a regular get packet. parsing stops\n");
					break;

				}
				line = strsep(&http_command, "\n");
			}
			result = check_for_php_attack(http_command3);
		}
		else if (strnicmp(http_command, "POST", 4) == 0){
			conn->type = HTTP_CONNECTED;
			strcpy(http_command4, http_command);
			strcpy(http_command3, http_command);
			result = check_coppermine_attack(http_command4);
			if (result == 1){
				if (search_for_data_leak(http_command3))
					result = -16;
			}
		}
		else{
			conn->type=HTTP_CONNECTED;
		}		
	}
	kfree(http_command4);
	kfree(http_command3);
	kfree(command_pointer);

	do_gettimeofday(&time_stamp);
	curr_time = time_stamp.tv_sec;
	conn->timestamp = curr_time;
	return result;

}

int update_smtp_connection(rule_t packet, struct tcphdr* tcphd, struct iphdr *iphd ,connection_node *curr_conn, unsigned char *tail, struct sk_buff *skb) {
	connection *conn = &curr_conn->conn;
	connection_node *opposite_conn;
	struct timeval time_stamp;
	unsigned long curr_time;
	int result = 1;
	int smtp_command_offset = iphd->ihl*4 + tcphd->doff*4; 
	int smtp_command_length = skb->len - smtp_command_offset;
	char *command_pointer;

	smtp_command =  kcalloc(smtp_command_length + 1,sizeof(char) , GFP_ATOMIC);
	skb_copy_bits(skb, smtp_command_offset , (void*)smtp_command, smtp_command_length);
	command_pointer = smtp_command;

	// START is all the initiation state, before data transfer.
	if (conn->type == SMTP_START){
		if (strstr(smtp_command, "DATA\r\n")!=NULL || strstr(smtp_command, "data\r\n")!=NULL) {
			conn->type = SMTP_CONNECTED;
			// find opposite connection and update it
			opposite_conn = find_opposite_connection(packet, tcphd);
			opposite_conn->conn.type = SMTP_CONNECTED;

		}
	}
	//check only outgoing data
	else if ((conn->type == SMTP_CONNECTED) && ntohs(conn->dst_port) == 25) {
		if (search_for_data_leak(smtp_command)){
			result = -16;
			// remove connection, this also removes other side
			close_connection(packet, tcphd, curr_conn);
		}
	}

	kfree(command_pointer);
	do_gettimeofday(&time_stamp);
	curr_time = time_stamp.tv_sec;
	conn->timestamp = curr_time;
	return result;
}

int update_gen_connection(rule_t packet, struct tcphdr* tcphd, connection_node *curr_conn){

	return 1;

}

int update_connection(rule_t packet, struct tcphdr* tcphd,struct iphdr *iphd ,connection_node *curr_conn, unsigned char *tail, struct sk_buff *skb){
	switch(curr_conn->conn.protocol){

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
			else if(curr_conn->conn.type == HTTP_ESTABLISHED || curr_conn->conn.type == HTTP_CONNECTED || curr_conn->conn.type == HTTP_END || curr_conn->conn.type == HTTP_HANDSHAKE){
				return update_http_connection(packet, tcphd, iphd ,curr_conn, tail, skb);
			}
			else if(curr_conn->conn.type == SMTP_CONNECTED || curr_conn->conn.type == SMTP_START || curr_conn->conn.type == SMTP_END){
				return update_smtp_connection(packet, tcphd, iphd ,curr_conn, tail, skb);
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
	connection_node *opposite_conn;

	if(conn->type == FTP_ESTABLISHED || conn->type == FTP_CONNECTED || conn->type == FTP_TRANSFER || conn->type == FTP_HANDSHAKE ){
		conn->type = FTP_END;
		conn->protocol = tcp_END;

	}
	else if(conn->type == HTTP_ESTABLISHED || conn->type == HTTP_CONNECTED || conn->type == HTTP_HANDSHAKE){
		conn->type = HTTP_END;
		conn->protocol = tcp_END;

	}
	else if(conn->type == SMTP_HANDSHAKE || conn->type == SMTP_CONNECTED){
		conn->type = SMTP_END;
		conn->protocol = tcp_END;
		opposite_conn = find_opposite_connection(packet, tcphd);
		opposite_conn->conn.type = SMTP_END;
		opposite_conn->conn.protocol = tcp_END;

	}

	else if (conn->type == TCP_GEN_ESTABLISHED ){
		conn->type = TCP_GEN_END;
		conn->protocol = tcp_END;
	}
	return 1;


}
	

/* Try and find a suitable connection for this new packet. */
int check_statful_inspection(rule_t packet, struct tcphdr *tcphd, struct iphdr *iphd ,unsigned int hooknum, unsigned char *tail, struct sk_buff *skb){
	struct timeval time_stamp;
	connection_node *curr_conn=NULL, *prev_conn=NULL;
	connection *conn;
	int i = 0;

	do_gettimeofday(&time_stamp);
	curr_conn=conn_tab_head;
	while (curr_conn != NULL){
		i++;
		conn = &curr_conn->conn;

		//is this connection timedout?
		// I use this to clean up connections
		if ((time_stamp.tv_sec - conn->timestamp) > 25 && (conn->protocol != tcp_ESTABLISHED || conn->protocol == tcp_END || conn->type == FTP_TRANSFER || (time_stamp.tv_sec - conn->timestamp) > 25*20)){
			printk("connection timeout, removing it.\n");
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
				return update_connection(packet, tcphd, iphd ,curr_conn, tail, skb);
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

	// no connection found, no opposite connection found, and no duplicate. this shouldn't happen.
	return 0;

}