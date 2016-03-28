#ifndef _HOOKFUNCS_H_
#define _HOOKFUNCS_H_

#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */ 
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h> 


/* index 1 is for the forward hook, index 2-3 is for input/output hooks
more on this at the Doc added */
struct nf_hook_ops hooks[3];
int cnt_blocked = 0, cnt_accepted = 0;


/* Functions */
int start_hooks(void);
int close_hooks(void);
unsigned int block_hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));
unsigned int pass_hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));

#endif