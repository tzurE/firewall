#ifndef _STATEFUL_FUNCS_H_
#define _STATEFUL_FUNCS_H_
#include "fw.h"
#include "hookfuncs.h"
#include "stateless_funcs.h"
#include "log.h"


typedef enum {
	FTP_HANDSHAKE,
	HTTP_HANDSHAKE,
	FTP_ESTABLISHED,
	HTTP_ESTABLISHED,
	HTTP_END,
	TCP_END
} tcp_type;


typedef enum {
	tcp_SYN_SENT_WAIT_SYN_ACK,
	tcp_SYN_ACK_SENT_WAIT_ACK,
	tcp_ACK_SENT,
	tcp_ESTABLISHED,
	tcp_END
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

int check_statful_inspection(rule_t packet, struct tcphdr *tcphd, unsigned int hooknum);
int create_new_connection(rule_t packet, int ack_state, int syn_state);

#endif // _STATEFUL_FUNCS_H_