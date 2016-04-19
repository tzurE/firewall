#include "fw.h"
#include "hookfuncs.h"

static int major_fw_rules;
static int major_fw_log;
static int minor_rules;
static int minor_log; 
static struct class* fw_class = NULL;
static struct device* fw_rules_device = NULL;
static struct device* fw_log_device = NULL;

extern int cnt_blocked;
extern int cnt_accepted;


/******* fw_rules functions and atts *******/
ssize_t get_rules(struct device *dev, struct device_attribute *attr, char *buf)	{
	char* msg = "This is get_rules\n";
	return scnprintf(buf, PAGE_SIZE, msg);
}

ssize_t set_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	{
	int temp;
	if (sscanf(buf, "%u", &temp) == 1){
		if (temp == 0){
			cnt_blocked = 0;
			cnt_accepted = 0;
		}
	}
	return count;	
}

//using sysfs to access it
static DEVICE_ATTR(rules_table, S_IRWXO , get_rules, set_rules);

static struct file_operations fops_rules = {
	.owner = THIS_MODULE
};

ssize_t get_fw_status(struct device *dev, struct device_attribute *attr, char *buf)	{
	char* msg = "This is get_fw_status!\n";
	return scnprintf(buf, PAGE_SIZE, msg);
}

ssize_t activate_fw(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	{
	return count;	
}

//using sysfs to access it
static DEVICE_ATTR(active, S_IRWXO , get_fw_status, activate_fw);

ssize_t get_rules_size(struct device *dev, struct device_attribute *attr, char *buf)	{
	char* msg = "This is get_rules_size!!\n";
	return scnprintf(buf, PAGE_SIZE, msg);
}

ssize_t demi_write(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	{
	return count;	
}

//using sysfs to access it
static DEVICE_ATTR(rules_size, S_IRWXO , get_rules_size, demi_write);

/******* fw_rules functions and atts end*******/



/******* fw_log functions and atts and size *******/
ssize_t get_log(struct device *dev, struct device_attribute *attr, char *buf){
	char* msg = "This is get_log\n";
	return scnprintf(buf, PAGE_SIZE, msg);
}

ssize_t demi_set_log(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	{
	return count;	
}

//using regular file ops to access device
static struct file_operations fops_log = {
	.write = demi_set_log,
	.read = get_log,
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
	printk(KERN_INFO "Strating Firewall\n");

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
	printk(KERN_INFO "Closing Firewall");
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
} 

/* As seen in class */
module_init(module_init_function);
module_exit(module_exit_function);

/* Every .c file requiers this. */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tzur Elyiahu");