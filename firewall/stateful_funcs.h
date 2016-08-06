#ifndef _STATEFUL_FUNCS_H_
#define _STATEFUL_FUNCS_H_
#include "fw.h"
#include "hookfuncs.h"
#include "stateless_funcs.h"
#include "log.h"
#include "exploits.h"


typedef enum {
	FTP_HANDSHAKE 		= 1,
	HTTP_HANDSHAKE 		= 2,
	FTP_ESTABLISHED 	= 3,
	HTTP_ESTABLISHED 	= 4,
	HTTP_END 			= 5,
	FTP_END 			= 6,
	TCP_GEN_HANDSHAKE 	= 7,
	TCP_GEN_ESTABLISHED = 8,
	TCP_GEN_END			= 9,
	FTP_CONNECTED 		= 10,
	HTTP_CONNECTED		= 11,
	FTP_TRANSFER		= 12,
} tcp_type;


typedef enum {
	tcp_SYN_SENT_WAIT_SYN_ACK 	= 1,
	tcp_SYN_ACK_SENT_WAIT_ACK 	= 2,
	tcp_ESTABLISHED 		  	= 4,
	tcp_END 				  	= 5,
} tcp_state;

// took the fields from the packet/log to create this struct
// each struct will represent a new connection in the connection table
// the connection table is actually a linked list
typedef struct {
	__be32 			src_ip;
	__be32 			dst_ip;
	__be16 			src_port;
	__be16 			dst_port;
	tcp_state 		protocol;
	tcp_type		type;
	__u16			id;
	__u16			frag_off;
	unsigned long 	timestamp;	
} connection;

// list of current connections
typedef struct connection_node {
	connection conn;
	struct connection_node *next;
} connection_node;


extern int num_of_conns;
extern connection_node *conn_tab_head;
extern connection_node *conn_tab_tail;
extern char *hosts_list;
extern int size_of_hosts;


int check_statful_inspection(rule_t packet, struct tcphdr *tcphd, struct iphdr *iphd, unsigned int hooknum, unsigned char *tail, struct sk_buff *skb);
connection_node* create_new_connection(rule_t packet, struct iphdr *iphd, int ack_state, int syn_state);
int is_connection_exists(rule_t packet, struct tcphdr *tcphd);
connection_node* insert_new_connection(connection_node* curr_conn);
connection_node* create_new_connection_node(rule_t packet, struct iphdr *iphd ,int ack_state, int syn_state);
int is_connection_exists_no_packet(connection_node * new_conn);
connection_node* find_opposite_connection(rule_t packet, struct tcphdr *tcphd);
int update_syn_sent(rule_t packet, struct tcphdr* tcphd, connection_node *curr_conn);
int update_syn_ack_sent(rule_t packet, struct tcphdr* tcphd, connection_node *curr_conn);
int update_ftp_connection(rule_t packet, struct tcphdr* tcphd, struct iphdr *iphd ,connection_node *curr_conn, unsigned char *tail);
int find_host_match(char* host_name);
int update_http_connection(rule_t packet, struct tcphdr* tcphd, struct iphdr *iphd ,connection_node *curr_conn, unsigned char *tail, struct sk_buff *skb);
int update_gen_connection(rule_t packet, struct tcphdr* tcphd, connection_node *curr_conn);
int update_connection(rule_t packet, struct tcphdr* tcphd,struct iphdr *iphd ,connection_node *curr_conn, unsigned char *tail, struct sk_buff *skb);
int close_connection(rule_t packet, struct tcphdr* tcphd, connection_node *curr_conn);


#endif // _STATEFUL_FUNCS_H_