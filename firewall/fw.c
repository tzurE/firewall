#include "fw.h"
#include "hookfuncs.h"
#include "stateless_funcs.h"

int firewall_activated = 0;
static int major_fw_rules;
static int major_fw_log;
static int minor_rules;
static int minor_log; 
static struct class* fw_class = NULL;
static struct device* fw_rules_device = NULL;
static struct device* fw_log_device = NULL;

extern int cnt_blocked;
extern int cnt_accepted;

//rules array
extern rule_t rules[50];
extern int num_rules;
char rules_raw[4090]="";


static int str_len;							// Length of 'test_String'
char* buffer_index;							// The moving index of the original buffer


/******* fw_rules functions and atts *******/
ssize_t get_rules(struct device *dev, struct device_attribute *attr, char *buf)	{
	return scnprintf(buf, PAGE_SIZE, rules_raw);
}

//get the rules from the user, parse it and insert it to the rules table
ssize_t set_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	{
	char *full_rules=NULL;
	char *full_rules_pointer=NULL;
	char *rule_line=NULL;
	int dir, src_cidr, dst_cidr, protocol, ack, action;
	unsigned int src_ip, dst_ip;
	short src_port, dst_port;
	rule_t rule;
	full_rules = kmalloc(count, GFP_ATOMIC);
	if(full_rules == NULL){
		printk(KERN_ERR "failed to allocate rules");
		return -1;
	}
	//copying rules so we can change it, becase buf is const
	strcpy(full_rules, buf);

	//saving rules start pointer, so we can free it at the end of this function
	full_rules_pointer = full_rules;

	// using strsep, doc from here: https://www.kernel.org/doc/htmldocs/kernel-api/API-strsep.html
	// http://www.gnu.org/software/libc/manual/html_node/Finding-Tokens-in-a-String.html
	rule_line = strsep(&full_rules, "\n");
	while (full_rules != NULL) {
		// printk("\n%s\n", rule_line);
		sscanf(rule_line, "%s %d %u %d %u %d %d %hd %hd %d %d", rule.rule_name, &dir, &src_ip, &src_cidr, &dst_ip, &dst_cidr, &protocol, &src_port, &dst_port, &ack, &action);
		// printk("%s, ", rule.rule_name);
		// printk("%d, ", dir);
		// printk("%u, %d, ", src_ip, src_cidr);
		// printk("%u, %d, ", dst_ip, dst_cidr);
		// printk("%d, %d, %d, %d, %d\n", protocol, src_port, dst_port, ack, action);

		//insert to array of "Get rules"

		strcat(rules_raw, rule_line);
		strcat(rules_raw, "\n");

		//insert everything to rule
		// direction: any=0, in=1, out=2
		if (dir == 0)
			rule.direction=DIRECTION_ANY;
		else if (dir == 1)
			rule.direction=DIRECTION_IN;
		else
			rule.direction=DIRECTION_OUT;

		//insert the ip (as is, no need to parse! already parsed on the user side)
		rule.src_ip=src_ip;
		rule.dst_ip=dst_ip;
		//src_mask is actually CIDR
		rule.src_prefix_size = src_cidr;
		rule.dst_prefix_size = dst_cidr;
		//http://stackoverflow.com/questions/1038002/how-to-convert-cidr-to-network-and-ip-address-range-in-c
		if (src_cidr == 0)
			rule.src_prefix_mask = 0;
		else {
			rule.src_prefix_mask = (0xFFFFFFFFu >> (32 - src_cidr));
		}
		if(dst_cidr == 0)
			rule.dst_prefix_mask = dst_cidr;
		else{
			rule.dst_prefix_mask = (0xFFFFFFFFu >> (32 - dst_cidr));
		}

		//protocol: 0=ICMP, 1=TCP, 2=UDP, 3=any, 4=OTHER
		if(protocol == 0)
			rule.protocol = PROT_ICMP;
		else if (protocol == 1)
			rule.protocol = PROT_TCP;
		else if (protocol == 2)
			rule.protocol = PROT_UDP;
		else if (protocol == 3)
			rule.protocol = PROT_ANY;
		else 
			rule.protocol = PROT_OTHER;

		//ports using 0 and 1023 as a convention.
		if (src_port == 0)
			rule.src_port = 0;
		else if (src_port == 1023)
			rule.src_port=1023;
		else
			rule.src_port = htons(src_port);
		if (dst_port == 0)
			rule.dst_port = 0;
		else if (dst_port == 1023)
			rule.dst_port=1023;
		else
			rule.dst_port = htons(dst_port);

		// ack! 0=any, 1=yes, 2=no
		if (ack == 0)
			rule.ack=ACK_ANY;
		else if (ack==1)
			rule.ack=ACK_YES;
		else if (ack == 2)
			rule.ack=ACK_NO;

		//action 1=accept, 0=drop
		if (action == 1)
			rule.action = NF_ACCEPT;
		else
			rule.action = NF_DROP;

		rules[num_rules] = rule;
		num_rules++;

		//getting next rule token
		rule_line = strsep(&full_rules, "\n");
	}
	// while(full_rules != "\0"){
	// 	printk("%s\n", full_rules );
	// }
	kfree(full_rules_pointer);
	return count;	
}

//using sysfs to access it
static DEVICE_ATTR(rules_table, S_IRWXO , get_rules, set_rules);

//and regular fops
static struct file_operations fops_rules = {
	.owner = THIS_MODULE
};

ssize_t get_fw_status(struct device *dev, struct device_attribute *attr, char *buf)	{
	char* msg = "";
	if (firewall_activated == 1)
		msg = "firewall active!\n";
	else 
		msg = "firewall is not active!\n";
	return scnprintf(buf, PAGE_SIZE, msg);
}

ssize_t activate_fw(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	{
	int temp;
	if (sscanf(buf, "%u", &temp) == 1){
		if (temp == 0 && firewall_activated == 1){
			printk(KERN_INFO "deactivating firewall");
			firewall_activated = 0;
		}
		if (temp == 1 && firewall_activated == 0){
			printk(KERN_INFO "activating firewall");
			firewall_activated = 1;
			
		}
	}
	return count;	
}

//using sysfs to access it
static DEVICE_ATTR(active, S_IRWXO , get_fw_status, activate_fw);

ssize_t get_rules_size(struct device *dev, struct device_attribute *attr, char *buf)	{
	char msg[6] = "";
	scnprintf(msg, 5, "%d\n", num_rules);
	return scnprintf(buf, PAGE_SIZE, msg);
}

ssize_t clear_rule_list(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	{
	rule_t empty;
	int i;
	int temp;
	if (sscanf(buf, "%u", &temp) == 1){
		if (temp == 0){
			printk(KERN_INFO "Deleting rule list\n");
			for (i=0; i < num_rules; i++){
				//setting num rules is enough. this is just extra.									
				rules[i]=empty;
			}
			memset(rules_raw,0,sizeof(rules_raw));
			strcpy(rules_raw, "");
			num_rules = 0;
		}
	}

	return count;	
}

//using sysfs to access it
static DEVICE_ATTR(rules_size, S_IRWXO , get_rules_size, clear_rule_list);

/******* fw_rules functions and atts end*******/



/******* fw_log functions and atts and size *******/
ssize_t get_log(struct file *filp, char *buff, size_t length, loff_t *offp){
	ssize_t num_of_bytes;
	char* msg = "This is get_log\n";
	scnprintf(buff, PAGE_SIZE, msg);
	num_of_bytes = (str_len < length) ? str_len : length;
    if (num_of_bytes == 0) { // We check to see if there's anything to write to the user
    	return 0;
	}
    if (copy_to_user(buff, buffer_index, num_of_bytes)) { // Send the data to the user through 'copy_to_user'
        return -EFAULT;
    } else { // fuction succeed, we just sent the user 'num_of_bytes' bytes, so we updating the counter and the string pointer index
        str_len -= num_of_bytes;
        buffer_index += num_of_bytes;
        return num_of_bytes;
    }

	return -EFAULT; // Should never reach here
}

ssize_t open_log(struct file *filp, const char *buff, size_t len, loff_t * off)	{
	str_len = strlen("This is get_log\n");
	buffer_index = "This is get_log\n";
	return 0;	
}

ssize_t demi_set_log(struct file *filp, const char *buff, size_t len, loff_t * off)	{
	return 1;	
}

//using regular file ops to access device
static struct file_operations fops_log = {
	.write = demi_set_log,
	.read = get_log,
	.open = open_log,
	.owner = THIS_MODULE
};

ssize_t get_log_size(struct device *dev, struct device_attribute *attr, char *buf){
	char* msg = "This is get_log_size";
	return scnprintf(buf, PAGE_SIZE, msg);

}

ssize_t set_log_size(struct device *dev, struct device_attribute *attr, char *buf){
	return 1;
}

static DEVICE_ATTR(log_size, S_IRWXO , get_log_size, set_log_size);

ssize_t clear_log(struct device *dev, struct device_attribute *attr, char *buf){
	int temp;
	if (sscanf(buf, "%u", &temp) == 1){
		if (temp == 0){
			cnt_blocked = 0;
			cnt_accepted = 0;
		}
	}
	return 1;
} 

ssize_t demi_clear_log(struct device *dev, struct device_attribute *attr, char *buf){
	return 1;
}

static DEVICE_ATTR(log_clear, S_IRWXO, demi_clear_log ,clear_log);

/******* fw_log functions and atts END *******/



static int __init module_init_function(void) {
	printk(KERN_INFO "Strating Firewall module\n");

	//create fw_rules device - as seen in class
	printk( KERN_INFO "register_chrdev\n" );
	major_fw_rules = register_chrdev(0, "fw_rules", &fops_rules);
	major_fw_log = register_chrdev(0, "fw_log", &fops_log);
	if ((major_fw_log < 0) || (major_fw_rules < 0))
		return -1;
		
	//create fw class - as seen in class
	fw_class = class_create(THIS_MODULE, "fw");
	if (IS_ERR(fw_class)){
		unregister_chrdev(major_fw_log, "fw_log");
		unregister_chrdev(major_fw_rules, "fw_rules");
		return -1;
	}
	
	minor_rules = MKDEV(major_fw_rules, 0);
	minor_log = MKDEV(major_fw_log, 0);

	//create rules device - as seen in class
	fw_rules_device = device_create(fw_class, NULL, minor_rules , NULL, "fw_rules");
	//create log device - as seen in class
	fw_log_device = device_create(fw_class, NULL, minor_log , NULL, "fw_log");	

	if (IS_ERR(fw_rules_device) || IS_ERR(fw_log_device))
	{
		class_destroy(fw_class);
		unregister_chrdev(major_fw_log, "fw_log");
		unregister_chrdev(major_fw_rules, "fw_rules");
		return -1;
	}
	
	//create sysfs file attributes - as seen in class
	if (device_create_file(fw_rules_device, (const struct device_attribute *)&dev_attr_rules_table.attr)){
		device_destroy(fw_class, minor_log);
		device_destroy(fw_class, minor_rules);
		class_destroy(fw_class);
		unregister_chrdev(major_fw_log, "fw_log");
		unregister_chrdev(major_fw_rules, "fw_rules");
		return -1;
	}
	device_create_file(fw_log_device, (const struct device_attribute *)&dev_attr_log_size.attr);
	device_create_file(fw_rules_device, (const struct device_attribute *)&dev_attr_active.attr);
	device_create_file(fw_rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
	device_create_file(fw_log_device, (const struct device_attribute *)&dev_attr_log_clear.attr);

	if (start_hooks() == -1 ){
		printk(KERN_INFO "Register hook failed. existing..");
		close_hooks();
		/* Clean everything up */
		device_remove_file(fw_rules_device, (const struct device_attribute *)&dev_attr_active.attr);
		device_remove_file(fw_rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
		device_remove_file(fw_rules_device, (const struct device_attribute *)&dev_attr_rules_table.attr);
		device_remove_file(fw_log_device, (const struct device_attribute *)&dev_attr_log_clear.attr);
		device_remove_file(fw_log_device, (const struct device_attribute *)&dev_attr_log_size.attr);
		device_destroy(fw_class, minor_log);
		device_destroy(fw_class, minor_rules);
		class_destroy(fw_class);
		unregister_chrdev(major_fw_log, "fw_log");
		unregister_chrdev(major_fw_rules, "fw_rules");
		return -1;
	}
	return 0;
}

static void __exit module_exit_function(void) {
	
	/* clean everything up */
	device_remove_file(fw_rules_device, (const struct device_attribute *)&dev_attr_active.attr);
	device_remove_file(fw_rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
	device_remove_file(fw_rules_device, (const struct device_attribute *)&dev_attr_rules_table.attr);
	device_remove_file(fw_log_device, (const struct device_attribute *)&dev_attr_log_clear.attr);
	device_remove_file(fw_log_device, (const struct device_attribute *)&dev_attr_log_size.attr);
	device_destroy(fw_class, minor_log);
	device_destroy(fw_class, minor_rules);
	class_destroy(fw_class);
	unregister_chrdev(major_fw_log, "fw_log");
	unregister_chrdev(major_fw_rules, "fw_rules");

	close_hooks();
	printk(KERN_INFO "Closing Firewall module");
} 

/* As seen in class */
module_init(module_init_function);
module_exit(module_exit_function);

/* Every .c file requiers this. */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tzur Elyiahu");