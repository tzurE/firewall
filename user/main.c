#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Basic program for reading and writing from a chardev */

int decode_line(char* rule_line, char* rule){
	char rule_name[20], src_buff[50]="", dst_buff[50]="";
	int dir, src_ip, src_cidr, dst_ip, dst_cidr, protocol, src_port, dst_port, ack, action;
	int src_any=0, dst_any=0;
	char *src_ip_str=NULL, *dst_ip_str=NULL;
	char src_str[90]="", dst_str[90]=""; 
	struct sockaddr_in src_ip_struct, dst_ip_struct;

	sscanf(rule_line, "%s %d %u %d %u %d %d %hd %hd %d %d", rule_name, &dir, &src_ip_struct.sin_addr, &src_cidr, &dst_ip_struct.sin_addr, &dst_cidr, &protocol, &src_port, &dst_port, &ack, &action);
		strcat(rule, rule_name);
		//insert everything to rule
		// direction: any=0, in=1, out=2
		if (dir == 0)
			strcat(rule, " any ");
		else if (dir == 1)
			strcat(rule, " in ");
		else
			strcat(rule, " out ");

		//insert the ip 
		src_ip_str = inet_ntoa(src_ip_struct.sin_addr);
		//must copy to use strcmp
		strcpy(src_buff, src_ip_str);
		if(strcmp("0.0.0.0", src_buff) != 0)
			strcat(rule, src_ip_str);
		else{
			strcat(rule, "any");
			src_any=1;
		}
		if (src_cidr != 32 && !src_any){
			strcat(rule, "/");
			sprintf(src_str, "%d", src_cidr);
			strcat(rule, src_str);
		}
		strcat(rule, " ");
		dst_ip_str = inet_ntoa(dst_ip_struct.sin_addr);
		strcpy(dst_buff, dst_ip_str);
		if (strcmp("0.0.0.0", dst_buff) != 0)
			strcat(rule, dst_ip_str);
		else{
			strcat(rule, "any");
			dst_any=1;
		}
		if (dst_cidr != 32 && !dst_any) {
			strcat(rule, "/");
			sprintf(dst_str, "%d", dst_cidr);
			strcat(rule, dst_str);
		}
		//protocol: 0=ICMP, 1=TCP, 2=UDP, 3=any, 4=OTHER
		if(protocol == 0)
			strcat(rule, " ICMP");
		else if (protocol == 1)
			strcat(rule, " TCP");
		else if (protocol == 2)
			strcat(rule, " UDP");
		else if (protocol == 3)
			strcat(rule, " any");
		else 
			strcat(rule, " other");

		//ports using 0 and 1023 as a convention.
		if (src_port == 0)
			strcat(rule, " any");
		else if (src_port == 1023 || src_port > 1023)
			strcat(rule, " >1023");
		else{
			sprintf(src_str, " %d", src_port);
			strcat(rule, src_str);
		}
		if (dst_port == 0)
			strcat(rule, " any");
		else if (dst_port == 1023 || dst_port > 1023)
			strcat(rule, " >1023");
		else{
			sprintf(dst_str, " %d", dst_port);
			strcat(rule, dst_str);
		}

		// ack! 0=any, 1=yes, 2=no
		if (ack == 0)
			strcat(rule, " any");
		else if (ack==1)
			strcat(rule, " yes");
		else if (ack == 2)
			strcat(rule, " no");

		//action 1=accept, 0=drop
		if (action == 1)
			strcat(rule, " accept\n");
		else
			strcat(rule, " drop\n");

}


char* encode_line(char * line, char* buff){
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
	int fd, fd2, count;
	char buff[200];
	char full_rules[4090]="";
	char *rule_line=NULL;

	if (argc < 2 ){
		printf ("error! wrong number of args! must use a command \n");
		return 0;
	}

	/* Load Rules */
	if (strcmp (argv[1], "load_rules")==0){
		fd = open("/sys/class/fw/fw_rules/rules_table", O_WRONLY);
		if (fd < 0 ){
			printf("error opening sysfs dev. check if it exists\n" );
			return -1;
		}
		FILE *rules = fopen(argv[2], "r");

		if (rules==NULL){
			perror("Error opening file! check that it exists and we have permissions!");
			close(fd);
			return -1;
		}

		char line[100]={0,};
		while(fgets(line, 100, rules) != NULL){
			char buff[90]="";
			encode_line(line, buff);
			strcat(full_rules, buff);			
		}
		write(fd, full_rules, strlen(full_rules));
		fclose(rules);
		close(fd);
		return;
	}

	/* Show Rules*/
	else if (strcmp(argv[1], "show_rules")==0){
		char *total_rules=NULL;
		char *total_rules_pointer=NULL;
		fd = open("/sys/class/fw/fw_rules/rules_table", O_RDONLY);
		if (fd < 0){
			printf("Error opening sysfs device rules_table, please make sure it exists\n");
			return -1;
		}
		
		total_rules = malloc(sizeof(char)*4090);
		total_rules_pointer = total_rules;
		count = read(fd, total_rules, 4090);
		close(fd);
		rule_line = strsep(&total_rules, "\n");
		while (total_rules != NULL){
			decode_line(rule_line, buff);
			strcat(full_rules, buff);
			rule_line = strsep(&total_rules, "\n");
			strcpy(buff, "");
		}
		free(total_rules_pointer);
		printf("%s", full_rules);
		return 1;

	}


	if (strcmp(argv[1], "clear_rules")==0){
		fd = open("/sys/class/fw/fw_rules/rules_size", O_WRONLY);
		if (fd < 0){
			printf("Error opening sysfs device rules_table, please make sure it exists\n");
			return -1;
		}
		write(fd, "0", 2);
		close(fd);
		return 1;

	}

	else if (strcmp(argv[1], "activate") == 0){
		char buff[40]="", buff2[40];
		fd = open("/sys/class/fw/fw_rules/active", O_RDWR);
		if (fd < 0){
			printf("Error opening sysfs device rules_table, please make sure it exists\n");
			return -1;
		}

		read(fd, buff,30);
		if (strcmp(buff, "firewall active!\n") == 0){
			printf("firewall already activated!\n");
		}
		else {
			count = write(fd, "1", 2);
			//check
			if(count != 0){
				printf("Firewall successfully activated\n");
				return 1;
			}
		}
	}

	if (strcmp(argv[1], "deactivate") == 0){
		char buff[40]="";
		fd = open("/sys/class/fw/fw_rules/active", O_RDWR);
		if (fd < 0){
			printf("Error opening sysfs device rules_table, please make sure it exists\n");
			return -1;
		}

		read(fd, buff,30);
		if (strcmp(buff, "firewall is not active!\n") == 0){
			printf("firewall already not active!\n");
		}
		else {
			count = write(fd, "0", 2);
			//check
			if(count != 0){
				printf("Firewall successfully deactivated\n");
				return 1;
			}
		}
	}

	if (strcmp(argv[1], "show_log") == 0){

	}

	if(strcmp(argv[1], "clear_log") == 0){

	}
	return 1;
}