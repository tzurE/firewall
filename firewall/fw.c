#include "fw.h"
#include "hookfuncs.h"

/*I've chosen to keep generic names, because I'm guessing this is onyl a practice run for the next assigment
there we would create meaningful devices, so in the meanwhile i've kept the names as general device. */
static int major_number;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;
static unsigned int sysfs_int = 0;

extern int cnt_blocked;
extern int cnt_accepted;

static struct file_operations fops = {
	.owner = THIS_MODULE
};

/* display and modify funcs, as seen in class */
ssize_t display(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show as seen in class
{
	char* msg = "Firewall Packets Summary:\n"
				"Number of accepted packets: %d \n"
				"Number of dropped packets: %d \n"
				"Total number of packets: %d \n";

	return scnprintf(buf, PAGE_SIZE, msg, cnt_accepted, cnt_blocked, (cnt_blocked+cnt_accepted), sysfs_int);
}

ssize_t modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store 
{
	int temp;
	if (sscanf(buf, "%u", &temp) == 1){
		if (temp == 0){
			cnt_blocked = 0;
			cnt_accepted = 0;
		}

	}

	return count;	
}


static DEVICE_ATTR(sysfs_att, S_IRWXO , display, modify);


static int __init module_init_function(void) {
	printk(KERN_INFO "Strating Firewall");

	//create char device - as seen in class
	major_number = register_chrdev(0, "Sysfs_Device", &fops);\
	if (major_number < 0)
		return -1;
		
	//create sysfs class - as seen in class
	sysfs_class = class_create(THIS_MODULE, "Sysfs_class");
	if (IS_ERR(sysfs_class))
	{
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}
	
	//create sysfs device - as seen in class
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, "sysfs_class" "_" "sysfs_Device");	
	if (IS_ERR(sysfs_device))
	{
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}
	
	//create sysfs file attributes - as seen in class
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr))
	{
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}

	if (start_hooks() == -1 ){
		printk(KERN_INFO "Register hook failed. existing..");
		close_hooks();
		/* Clean everything up */
		device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr);
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}
	return 0;
}

static void __exit module_exit_function(void) {
	printk(KERN_INFO "Closing Firewall");
	/* clean everything up */
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr);
	device_destroy(sysfs_class, MKDEV(major_number, 0));
	class_destroy(sysfs_class);
	unregister_chrdev(major_number, "Sysfs_Device");
	close_hooks();
} 

/* As seen in class */
module_init(module_init_function);
module_exit(module_exit_function);

/* Every .c file requiers this. */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tzur Elyiahu");