
#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */ 
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h> 
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* declaring them as extern so everyone knows it's defined at hookfuncs.c */
extern struct nf_hook_ops hooks[3];
extern int cnt_blocked;
extern int cnt_accepted;

/* Functions */
int start_hooks(void);
int close_hooks(void);
unsigned int block_hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));
unsigned int pass_hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));