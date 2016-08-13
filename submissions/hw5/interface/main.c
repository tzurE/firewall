#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Basic program for reading and writing from a chardev */
int parse_conn_line(char* conn_line, char* buff){
	char temp[50];
	struct sockaddr_in src_ip_struct, dst_ip_struct;
	unsigned long timestamp;
	int protocol, src_port, dst_port, type;
	char *timestamp_string, *src_ip_str, *dst_ip_str, src_ip_str_dem[30];

	sscanf(conn_line, "%lu %u %u %u %u %u %u", &timestamp, &src_ip_struct.sin_addr, &dst_ip_struct.sin_addr, &src_port, &dst_port, &protocol, &type);

	timestamp_string = ctime((const time_t *) &timestamp);
	timestamp_string[strlen(timestamp_string) - 1] = ' ';
	strcat(buff, timestamp_string);
	strcat(buff, " ");

	src_ip_str = inet_ntoa(src_ip_struct.sin_addr);
	//need to copy because inet_ntoa return actually a cons char *
	strcpy(src_ip_str_dem, src_ip_str);
	dst_ip_str = inet_ntoa(dst_ip_struct.sin_addr);
	strcat(buff, src_ip_str_dem);
	strcat(buff, " ");
	strcat(buff, dst_ip_str);
	sprintf(temp, " %d %d ", src_port, dst_port);
	strcat(buff, temp);

	if (protocol == 1)
		strcat(buff, " tcp_SYN_SENT_WAIT_SYN_ACK ");
	else if (protocol == 2)
		strcat(buff, " tcp_SYN_ACK_SENT_WAIT_ACK ");
	else if(protocol == 3)
		strcat(buff, " tcp_ACK_SENT ");
	else if (protocol == 4)
		strcat(buff, " tcp_ESTABLISHED ");
	else if (protocol == 5)
		strcat(buff, " tcp_END ");

	if (type == 1)
		strcat(buff, " FTP_HANDSHAKE ");
	else if (type == 2)
		strcat(buff, " HTTP_HANDSHAKE ");
	else if(type == 3)
		strcat(buff, " FTP_ESTABLISHED ");
	else if (type == 4)
		strcat(buff, " HTTP_ESTABLISHED ");
	else if (type == 5)
		strcat(buff, " HTTP_END (End state is cleaned up after 25 secs) ");
	else if (type == 6)
		strcat(buff, " FTP_END (End state is cleaned up after 25 secs) ");
	else if (type == 7)
		strcat(buff, " TCP_GEN_HANDSHAKE ");
	else if (type == 8)
		strcat(buff, " TCP_GEN_ESTABLISHED ");
	else if (type == 9)
		strcat(buff, " TCP_GEN_END (End state is cleaned up after 25 secs) ");
	else if (type == 10)
		strcat(buff, " FTP_CONNECTED ");
	else if (type == 11)
		strcat(buff, " HTTP_CONNECTED ");
	else if (type == 12)
		strcat(buff, " FTP_TRANSFER (removed automatically if not updated in 25 secs) ");
	else if (type == 13)
		strcat(buff, " SMTP_HANDSHAKE ");
	else if (type == 14)
		strcat(buff, " SMTP_START ");
	else if (type == 15)
		strcat(buff, " SMTP_CONNECTED ");
	else if (type == 16)
		strcat(buff, " SMTP_END ");

	strcat(buff, "\n");
	return 1;


}

int decode_log_line(char* log_line, char* buff){
	char temp[30];
	struct sockaddr_in src_ip_struct, dst_ip_struct;
	unsigned long timestamp;
	int protocol, action, hooknum;
	int src_port, dst_port;
	int reason, count;
	char *timestamp_string, *src_ip_str, *dst_ip_str, src_ip_str_dem[30];
	// printf("%s\n", log_line);
	sscanf(log_line, "%lu %d %d %d %u %u %d %d %d %u", &timestamp, &protocol, &action, &hooknum, &src_ip_struct.sin_addr, &dst_ip_struct.sin_addr, &src_port, &dst_port, &reason, &count);
	// printf("%lu, %d, %d, %d\n", timestamp, protocol, action, hooknum);

	//parse time http://www.tutorialspoint.com/c_standard_library/c_function_ctime.htm
	timestamp_string = ctime((const time_t *) &timestamp);
	//ctime puts \n at the end of the string.
	timestamp_string[strlen(timestamp_string) - 1] = ' ';
	strcat(buff, timestamp_string);
	strcat(buff, " ");

	//parse ips
	src_ip_str = inet_ntoa(src_ip_struct.sin_addr);
	//need to copy because inet_ntoa return actually a cons char *
	strcpy(src_ip_str_dem, src_ip_str);
	dst_ip_str = inet_ntoa(dst_ip_struct.sin_addr);
	strcat(buff, src_ip_str_dem);
	strcat(buff, " ");
	strcat(buff, dst_ip_str);
	sprintf(temp, " %d %d", src_port, dst_port);
	strcat(buff, temp);

	// printf("%s, %s, %u, %u\n", timestamp_string, src_ip_str, src_port, dst_port);
	//protocol
	if (protocol == 1)
		strcat(buff, " icmp ");
	else if (protocol == 6)
		strcat(buff, " tcp ");
	else if (protocol == 17)
		strcat(buff, " udp ");
	else
		strcat(buff, " other ");

	sprintf(temp, "%d ", hooknum);
	strcat(buff, temp);

	if (action == 1)
		strcat(buff, "accept ");
	else 
		strcat(buff, "drop ");

	if (reason == -1)
		strcat(buff, "REASON_FW_INACTIVE");
	else if (reason == -2)
		strcat(buff, "REASON_NO_MATCHING_RULE");
	else if (reason == -4)
		strcat(buff, "REASON_XMAS_PACKET");
	else if (reason == -6)
		strcat(buff, "REASON_ILLEGAL_VALUE");
	else if(reason == -8)
		strcat(buff, "REASON_CONN_NOT_EXIST");
	else if (reason == -12)
		strcat(buff, "REASON_HOSTS_BLOCKED");
	else if (reason == -14)
		strcat(buff, "REASON_PHP_ATTACK");
	else if (reason == -16)
		strcat(buff, "REASON_COPPERMINE_ATTACK");
	else if (reason == -18)
		strcat(buff, "REASON_DLP");
	else {
		sprintf(temp, " %d ", reason);
		strcat(buff, temp);
	}

	sprintf(temp, " %u\n", count);
	strcat(buff, temp);
	return 1;
}

int decode_line(char* rule_line, char* rule){
	char rule_name[20], src_buff[50]="", dst_buff[50]="";
	int dir, src_ip, src_cidr, dst_ip, dst_cidr, protocol, src_port, dst_port, ack, action;
	int src_any=0, dst_any=0;
	char *src_ip_str=NULL, *dst_ip_str=NULL;
	char src_str[90]="", dst_str[90]=""; 
	struct sockaddr_in src_ip_struct, dst_ip_struct;

	sscanf(rule_line, "%s %d %u %d %u %d %d %d %d %d %d", rule_name, &dir, &src_ip_struct.sin_addr, &src_cidr, &dst_ip_struct.sin_addr, &dst_cidr, &protocol, &src_port, &dst_port, &ack, &action);
		//insert everything to rule
		// direction: any=0, in=1, out=2
		strcat(rule, rule_name);

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


int encode_line(char * line, char* buff){
	char buffer[120];
	struct sockaddr_in src;
	struct sockaddr_in dst;
	char rule[100]="", full_src_ip[18]="", full_dst_ip[18]="", src_ip[14]="", dst_ip[14]="";
	char name[20]="";
	char dir[5]="", protocol[10]="", ack[7]="", action[30]="", src_port[8]="", dst_port[8]="";
	int src_ip_mask, dst_ip_mask, counts;
	char *point, *some1, *some;
	counts = sscanf(line, "%s %s %s %s %s %s %s %s %s", name, dir, full_src_ip, full_dst_ip, protocol, src_port, dst_port, ack, action);
	
	if(counts == EOF){
		return -1;
	}
	if (counts != 9 && counts != EOF){
		return -2;
	}

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
	//if it's a bad address
	if(inet_aton(src_ip, &src.sin_addr) == 0){
		printf("Error parsing ip: %s\n", src_ip);
		return -2;
	}
	if (inet_aton(dst_ip, &dst.sin_addr) == 0){
		printf("Error parsing ip: %s\n", dst_ip);
		return -2;
	}
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
	else if(strcmp("no", ack) == 0)
		strcat(rule, " 2");
	else{
		printf("Error parsing ack: %s\n", ack);
		return -2;
	}

	//parse action: 1=accept, 0=drop
	if(strcmp("accept", action)==0)
		strcat(rule, " 1");
	else if (strcmp("drop", action) == 0)
		strcat(rule, " 0");
	else{
		printf("Error parsing action: %s\n", action);
		return -2;
	}

	strcat(rule, "\n");
	sprintf(buff, "%s", rule);
	return 1;
}

int clear_rules_func(){
	int fd;
	fd = open("/sys/class/fw/fw_rules/clear_rules", O_WRONLY);
	if (fd < 0){
		printf("Error opening sysfs device clear_rules, please make sure it exists\n");
		return -1;
	}
	write(fd, "0", 2);
	close(fd);
	return 1;
}

int main(int argc, const char *argv[]) {
	int fd, fd2, count;
	char buff[200]="";
	char full_rules[4090]="";
	char *full_hosts=NULL;
	char *rule_line=NULL;
	if (argc < 2 ){
		printf ("error! wrong number of args! must use a command \n");
		return 0;
	}

	/* Load Rules */
	if (strcmp (argv[1], "load_rules")==0){
		//first clear rules
		clear_rules_func();

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
		int retval;
		while(fgets(line, 100, rules) != NULL){
			char buff[90]="";
			retval =  encode_line(line, buff);
			if(retval == -1) //EOF, finish this
				break;
			if(retval == -2){
				printf("Error! line parsing failed. make sure that the file is well formatted and each line is built as follows:\n");
				printf("<rule_name> <direction> <Source_IP>/<nps> <Dest_IP>/<nps> <protocol><Source_port> <Dest_port> <ack> <action>\n");
				fclose(rules);
				close(fd);
				return;
			}
			strcat(full_rules, buff);			
		}
		// printf("%s", full_rules);
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
		strcmp(buff, "");
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
		return clear_rules_func();
		// fd = open("/sys/class/fw/fw_rules/clear_rules", O_WRONLY);
		// if (fd < 0){
		// 	printf("Error opening sysfs device clear_rules, please make sure it exists\n");
		// 	return -1;
		// }
		// write(fd, "0", 2);
		// close(fd);
		// return 1;

	}

	else if (strcmp(argv[1], "activate") == 0){
		char buff[40]="", buff2[40];
		fd = open("/sys/class/fw/fw_rules/active", O_RDWR);
		if (fd < 0){
			printf("Error opening sysfs device active, please make sure it exists\n");
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
			printf("Error opening sysfs device active please make sure it exists\n");
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
		int sizefd, log_size;
		char log_size_str[16];
		char *log_to_user=NULL, *full_log;
		char* log_line=NULL;
		char *log_to_user_pointer;
		fd = open("/dev/fw_log", O_RDONLY);
		if (fd < 0){
			printf("Error opening fw_log device, please make sure it exists\n");
			return -1;
		}
		sizefd = open("/sys/class/fw/fw_log/log_size", O_RDONLY);
		if (sizefd < 0){
			printf("Error getting size of log.\n");
			return -1;
		}
		read(sizefd, log_size_str, 16);
		sscanf(log_size_str, "%d", &log_size);
		log_to_user = calloc(log_size*100, sizeof(char));
		log_to_user_pointer=log_to_user;
		// printf("log size: %d\n", log_size);
		while (read(fd, buff, 190) != 0){
			strcat(log_to_user, buff);
			strcpy(buff, "");
		}
		printf("timestamp  src_ip  dst_ip  src_port  dst_port  protocol  hooknum  action  reason  count\n");
		//now to parse it!
		log_line = strsep(&log_to_user, "\n");
		strcpy(buff, "");
		while (log_to_user != NULL){
			decode_log_line(log_line, buff);
			printf("%s", buff);
			log_line = strsep(&log_to_user, "\n");
			strcpy(buff, "");

		}
		free(log_to_user_pointer);

	}

	if(strcmp(argv[1], "clear_log") == 0){
		fd = open("/sys/class/fw/fw_log/log_clear", O_WRONLY);
		if (fd < 0){
			printf("Error opening fw_log device, please make sure it exists\n");
			return -1;
		}
		write(fd, "c", 2);
		close(fd);
		return 1;

	}

	else if (strcmp(argv[1], "show_connection_table") == 0){
		int sizefd, conn_size;
		char conn_size_str[16];
		char* conn_to_user=NULL;
		char* conn_to_user_pointer=NULL;
		char* conn_line;
		fd = open("/dev/fw_conn_tab", O_RDONLY);
		if (fd < 0){
			printf("Error opening connections device, please make sure it exists\n");
			return -1;
		}
		//get conn table size. used another device for the size:
		sizefd = open("/sys/class/fw/fw_log/log_clear", O_RDONLY);
		if (sizefd < 0){
			printf("Error getting number of connections.\n");
			return -1;
		}
		read(sizefd, conn_size_str, 16);
		sscanf(conn_size_str, "%d", &conn_size);
		conn_to_user = calloc(conn_size*80, sizeof(char));
		conn_to_user_pointer=conn_to_user;

		while (read(fd, buff, 190) != 0){
			strcat(conn_to_user, buff);
			strcpy(buff, "");
		}
		printf("<Timestamp> <Source_IP> <Dest_IP> <Source_port> <Dest_port> <protocol/state> <Type>\n");
		conn_line = strsep(&conn_to_user, "\n");
		strcpy(buff, "");
		while (conn_to_user != NULL){
			parse_conn_line(conn_line, buff);
			printf("%s", buff);
			conn_line = strsep(&conn_to_user, "\n");
			strcpy(buff, "");

		}
		free(conn_to_user_pointer);
		return 1;

	}
	else if (strcmp(argv[1], "show_hosts") == 0){
		char block[101] = "";
		fd = open("/sys/class/fw/hosts/hosts", O_RDONLY);
		if (fd < 0){
			printf("Error opening sysfs device hosts, please make sure it exists\n");
			return -1;
		}
		
		count = read(fd, block, 100);
		while (count != 0){
			printf("%s", block);
			count = read(fd, block, 100);

		}
		close(fd);
		return 1;


	}
	else if (strcmp(argv[1], "load_hosts") == 0){
		int buff_size;
		fd = open("/sys/class/fw/hosts/hosts", O_WRONLY);
		if (fd < 0 ){
			printf("error opening sysfs device hos. check if it exists\n" );
			return -1;
		}
		FILE *hosts_file = fopen(argv[2], "r");

		if (hosts_file==NULL){
			perror("Error opening file! check that it exists and we have permissions!");
			close(fd);
			return -1;
		}

		char line[100]={0,};
		int c;
		while (c=fgetc(hosts_file)){
			buff_size++;
			if (c == EOF)
				break;
		}
		rewind(hosts_file);
		full_hosts = (char*)malloc(sizeof(char)*buff_size + 10);
		while(fgets(line, 100, hosts_file) != NULL){
			strcat(full_hosts, line);			
		}
		strcat(full_hosts, "\n");
		write(fd, full_hosts, strlen(full_hosts));
		free(full_hosts);
		fclose(hosts_file);
		close(fd);
		return;

	}
	return 1;
}