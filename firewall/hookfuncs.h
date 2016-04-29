#ifndef _HOOKFUNCS_H_
#define _HOOKFUNCS_H_

#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */ 
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h> 
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "fw.h"

/* declaring them as extern so everyone knows it's defined at hookfuncs.c */
extern struct nf_hook_ops hooks[3];

/* Functions */
int start_hooks(void);
int close_hooks(void);
int parse_packet(struct sk_buff *skb, const struct net_device *in, unsigned int hooknum, int dir);
unsigned int input_hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));
unsigned int output_hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));

#endif // _HOOKFUNCS_H_