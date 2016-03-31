#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>

int main(int argc, const char *argv[]) {
	int fd;

	if (argc > 2 ){
		printf ("error! wrong number of args! \n");
		return 0;
	}
	fd = open("/sys/class/Sysfs_class/sysfs_class_sysfs_Device/sysfs_att", O_RDWR);
	if (fd < 0 ){
		printf("error opening sysfs dev. check if it exists\n" );
		return 0;
	}

	if (argc == 2){
		if (strcmp(argv[1],"0\0") == 0){
			write(fd, "0", 1);
		}
	}
	else{
		char buff[120];
		read(fd, buff, 119);
		printf("%s", buff);
	}

	close(fd);
}