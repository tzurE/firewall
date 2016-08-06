#ifndef _FW_H_
#define _FW_H_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <linux/string.h>


// the protocols we will work with
typedef enum {
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_OTHER 	= 255,
	PROT_ANY	= 143,
} prot_t;


// various reasons to be registered in each log entry
typedef enum {
	REASON_FW_INACTIVE           = -1,
	REASON_NO_MATCHING_RULE      = -2,
	REASON_XMAS_PACKET           = -4,
	REASON_ILLEGAL_VALUE         = -6,
	REASON_CONN_NOT_EXIST		 = -8,
	REASON_CONN_NOT_COMPLINT	 = -10,
	REASON_HOSTS_BLOCKED		 = -12,
	REASON_PHP_ATK				 = -14,
	REASON_COP_ATK				 = -16,
} reason_t;
	

// auxiliary strings, for your convenience
#define DEVICE_NAME_RULES			"rules"
#define DEVICE_NAME_LOG				"log"
#define DEVICE_NAME_CONN_TAB		"conn_tab"
#define CLASS_NAME					"fw"
#define LOOPBACK_NET_DEVICE_NAME	"lo"
#define IN_NET_DEVICE_NAME			"eth1"
#define OUT_NET_DEVICE_NAME			"eth2"

// auxiliary values, for your convenience
#define IP_VERSION		(4)
#define PORT_ANY		(0)
#define PORT_ABOVE_1023	(1023)
#define MAX_RULES		(50)

// device minor numbers, for your convenience
typedef enum {
	MINOR_RULES    = 0,
	MINOR_LOG      = 1,
} minor_t;

typedef enum {
	ACK_NO 		= 0x01,
	ACK_YES 	= 0x02,
	ACK_ANY 	= ACK_NO | ACK_YES,
} ack_t;

typedef enum {
	DIRECTION_IN 	= 0x01,
	DIRECTION_OUT 	= 0x02,
	DIRECTION_ANY 	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;

// rule base
typedef struct {
	char rule_name[20];			// names will be no longer than 20 chars
	direction_t direction;
	__be32	src_ip;
	__be32	src_prefix_mask; 	// e.g., 255.255.255.0 as int in the local endianness
	__u8    src_prefix_size; 	// valid values: 0-32, e.g., /24 for the example above
								// (the field is redundant - easier to print)
	__be32	dst_ip;
	__be32	dst_prefix_mask; 	// as above
	__u8    dst_prefix_size; 	// as above	
	__be16	src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	__be16	dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	__u8	protocol; 			// values from: prot_t
	ack_t	ack; 				// values from: ack_t
	__u8	action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;

// logging
typedef struct {
	unsigned long  	timestamp;     	// time of creation/update
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	unsigned char  	hooknum;      	// as received from netfilter hook
	__be32   		src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be32			dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be16 			src_port;	  	// if you use this struct in userspace, change the type to unsigned short
	__be16 			dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
	reason_t     	reason;       	// rule#index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits
} log_row_t;


extern int firewall_activated;
extern char rules_raw[4090];

ssize_t get_rules(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t clear_rule_list_func(const char *buf, size_t count);
ssize_t set_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
ssize_t get_fw_status(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t activate_fw(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
ssize_t get_rules_size(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t rules_size_demi(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
ssize_t clear_demi(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t clear_rule_list(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
ssize_t get_log(struct file *filp, char *buff, size_t length, loff_t *off);
ssize_t open_log(struct inode *inode, struct file *file);
ssize_t demi_set_log(struct file *filp, const char *buff, size_t len, loff_t * off);
ssize_t get_log_size(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t set_log_size(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
ssize_t clear_log(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
ssize_t demi_clear_log(struct device *dev, struct device_attribute *attr, char *buf);


#endif // _FW_H_