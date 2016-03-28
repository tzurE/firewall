#include "hw2secws.h"
#include "hookfuncs.h"


MODULE_AUTHOR("Tzur Elyiahu");


static struct file_operations fops = {
	.owner = THIS_MODULE
};


int __init module_init_function(void) {

	if (start_hooks() == -1 ){
		printk(KERN_INFO "Register hook failed. existing..");
		close_hooks();
		return -1;
	}
	return 0;
}

void __exit module_exit_function(void) {
	close_hooks();
} 

/* As seen in class */
module_init(module_init_function);
module_exit(module_exit_function);