obj-m := firewall.o
firewall-objs :=fw.o hookfuncs.o stateless_funcs.o log.o
KBUILD_CFLAGS += -w

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) $(KBUILD_CFLAGS) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean 