#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Basic program for reading and writing from a chardev */
char* translate_line(char * line, char* buff){
	char buffer[120];
	struct sockaddr_in src;
	struct sockaddr_in dst;
	char rule[100]="", full_src_ip[18]="", full_dst_ip[18]="", src_ip[14]="", dst_ip[14]="";
	char name[20]="";
	char dir[5]="", protocol[10]="", ack[7]="", action[30]="", src_port[8]="", dst_port[8]="";
	int src_ip_mask, dst_ip_mask;
	char *point, *some1, *some;
	sscanf(line, "%s %s %s %s %s %s %s %s %s", name, dir, full_src_ip, full_dst_ip, protocol, src_port, dst_port, ack, action);
	
	strcat(rule, name);
	//parse direction: any=0, in=1, out=2
	if(strcmp("any", dir) == 0)
		strcat(rule, " 0 ");
	else if (strcmp("in", dir)==0)
		strcat(rule, " 1 ");
	else
		strcat(rule, " 2 ");

	//parse the ip and turn it to string
	//https://beej.us/guide/bgnet/output/html/multipage/inet_ntoaman.html
	if (strcmp("any", full_src_ip) == 0){
		strcpy(full_src_ip, "0.0.0.0/0");
	}
	point = strstr(full_src_ip, "/");
	if (point == NULL){
		src_ip_mask=32;
		strcpy(src_ip, full_src_ip);
	}
	else{
		strstr(full_src_ip, "/")[0]= ' ';
		sscanf(full_src_ip, "%s %d", src_ip, &src_ip_mask);
	}
	if (strcmp("any", full_dst_ip)==0){
		strcpy(full_dst_ip, "0.0.0.0/0");
	}
	point="";
	point = strstr(full_dst_ip, "/");
	if (point == NULL){
		dst_ip_mask=32;
		strcpy(dst_ip, full_dst_ip);
	}
	else{
		strstr(full_dst_ip, "/")[0] = ' ';
		sscanf(full_dst_ip, "%s %d", dst_ip, &dst_ip_mask);
	}
	//convert to unsigned int
	inet_aton(src_ip, &src.sin_addr);
	inet_aton(dst_ip, &dst.sin_addr);
	//insert to buffer and then concat to translated rule
	sprintf(buffer, "%u %d %u %d", src.sin_addr, src_ip_mask , dst.sin_addr, dst_ip_mask);
	strcat(rule,buffer);
	
	//parse protocol: 0=ICMP, 1=TCP, 2=UDP, 3=any, 4=OTHER
	if (strcmp("ICMP", protocol)==0 || strcmp("icmp", protocol)==0)
		strcat(rule, " 0");
	else if(strcmp("TCP", protocol)==0 || strcmp("tcp", protocol)==0)
		strcat(rule, " 1");
	else if(strcmp("UDP", protocol)==0 || strcmp("udp", protocol)==0)
		strcat(rule, " 2");
	else if(strcmp("any", protocol)==0)
		strcat(rule, " 3");
	else 
		strcat(rule, " 4");

	//parse ports: just pass them as they are if they are a specific number. otherwise, a string.
	if (strcmp("any", src_port)==0)
		strcat(rule, " 0");
	else if(strcmp(">1023", src_port)==0)
		strcat(rule, " 1023");
	else{
		strcat(rule, " ");
		strcat(rule, src_port);
	}

	if (strcmp("any", dst_port)==0)
		strcat(rule, " 0");
	else if(strcmp(">1023", dst_port)==0)
		strcat(rule, " 1023");
	else{
		strcat(rule, " ");
		strcat(rule, dst_port);
	}

	//parse ack: 0=any, 1=yes, 2=no
	if (strcmp("any", ack) == 0)
		strcat(rule, " 0");
	else if (strcmp("yes", ack) == 0)
		strcat(rule, " 1");
	else 
		strcat(rule, " 2");

	//parse action: 1=accept, 0=drop
	if(strcmp("accept", action)==0)
		strcat(rule, " 1");
	else 
		strcat(rule, " 0");

	strcat(rule, "\n");
	sprintf(buff, "%s", rule);
	// printf("%s", rule);
	// strcat(rule, " ");
	// strcat(rule, src_ip_mask);
	// strcat(rule, " ");
	// printf("%s, %d\n", src_ip, src_ip_mask);
	// printf("%s, %d\n", dst_ip, dst_ip_mask);
	// printf("%u\n", src.sin_addr);
	// printf("%u\n", dst.sin_addr);
	// some = inet_ntoa(src.sin_addr); // return the IP
	// some1 = inet_ntoa(dst.sin_addr);
	// printf("%s\n", some);
	// printf("%s\n", some1);
	//http://stackoverflow.com/questions/1680622/ip-address-to-integer-c
	// unsigned int c1,c2,c3,c4;
	// sscanf(src_ip_str, "%d.%d.%d.%d",&c1,&c2,&c3,&c4);
	// unsigned long ip = (unsigned long)c4+c3*256+c2*256*256+c1*256*256*256;
	// printf("The unsigned long integer is %lu\n",ip);
	// printf("%s\n", name);
	// printf("%s, %s\n" ,full_src_ip, full_dst_ip);
	// printf("%s\n", dir);
	// printf("%s, %s, %s, akc: %s, action: %s\n", protocol, src_port, dst_port, ack, action);
	// printf("%d, %d, %d, %d \n", src_ip, src_ip_mask, dst_ip, dst_ip_mask);
	// printf("%d %d %d %d %d\n",protocol, src_port, dst_port, ack, action );
	return "";
}

int main(int argc, const char *argv[]) {
	int fd;
	char buff[200];

	if (argc < 2 ){
		printf ("error! wrong number of args! \n");
		return 0;
	}
	if (strcmp (argv[1], "load_rule_table_from_file")==0){
		fd = open("/sys/class/fw/fw_rules/rules_table", O_WRONLY);
		if (fd < 0 ){
			printf("error opening sysfs dev. check if it exists\n" );
			return 0;
		}
		FILE *rules = fopen(argv[2], "r");

		if (rules==NULL){
			perror("Error opening file! check that it exists and we have permissions!");
			close(fd);
			return -1;
		}

		char line[100]={0,};
		char full_rules[4090]="";
		while(fgets(line, 100, rules) != NULL){
			char buff[90]="";
			translate_line(line, buff);
			strcat(full_rules, buff);			
		}
		printf("%s", full_rules);
		write(fd, full_rules, strlen(full_rules));
		fclose(rules);
		close(fd);
	}
	return 1;
}