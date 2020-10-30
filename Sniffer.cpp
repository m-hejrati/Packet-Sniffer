#include <locale>
#include <json-c/json.h>
#include "spdlog/spdlog.h"
#include <string>

using namespace std;


#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <syslog.h>

#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header

#include<signal.h>
#include<unistd.h>


// this class save protocol feature
class Protocol {

private:
	int tcpudp_10 = -1;
	int ip_13 = -1;
	int ip_14 = -1;

public:
	// setter
    void setTcpudp_10(int tu) {
      tcpudp_10 = tu;
    }
    void setIp_13(int tu) {
      ip_13 = tu;
    }
    void setIp_14(int tu) {
      ip_14 = tu;
    }

    // getter
    int getTcpudp_10() {
      return tcpudp_10;
    }
    int getIp_13() {
      return ip_13;
    }
    int getIp_14() {
      return ip_14;
    }

};

// this class log important event of the program
class Logger {

private:
	string type;

public:
	// setter
    void setType(string t) {
      type = t;
    }

    // getter
    string getType() {
      return type;
    } 

	// constructor of Logger class
	Logger(string typ){
		type = typ;
	}
	
	// get message and log with choose level
    void log(string message){

	    if (type == "debug")

			spdlog::debug(message);					

		else if (type == "info")

			spdlog::info(message);
	
		else if (type == "warn")

			spdlog::warn(message);
			
		else if (type == "warn")

			spdlog::error(message);

		else if (type == "critical")
		
			spdlog::critical(message);
	}

};

// create global logger object to use it all over the program
Logger logger("0");


// number of captured packets
int packet_number = 0;
int tcp_number = 0;
int udp_number = 0;
int ipv4_number = 0;
int ipv6_number = 0;
int arp_number = 0;

// an struct to hold name and ip of packets
struct device {

	char name [20];
	char ip [16];
};

// an struct to hold source and destination of a packet 
struct IP {

	char src [16];
	char dst [16];
};


// find and save prinatble part of payload
char* find_printable_payload(const u_char *payload, int len){

	const u_char *ch = payload;
	char printable[10000] = "";
	int j = 0;
	
	// find printable character and save them into a new string.
	for(int i = 0; i < len; i++) {

		if (isprint(*ch)){
			printable[j] = *ch;
			j++;

		} else if ((*ch) == '\n' || (*ch) == ' '){
            printable[j] = *ch;
			j++;
        }

		ch++;
	}
	
	char* tmp = printable;
	return tmp;
}

// print useful data of ip header
void print_ip_header(int Size, struct IP ip) {
	
	char buff [50];
    sprintf(buff, "Packet size: %d bytes", Size);
	logger.log(buff);
    sprintf(buff, "     Src IP: %s", ip.src);
	logger.log(buff);
    sprintf(buff, "     Dst IP: %s", ip.dst);
	logger.log(buff);
}

// separate useful part of ip header
struct IP Processing_ip_header(const u_char * Buffer, int Size) {

	struct sockaddr_in source,dest;
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	
	// get source IP address
    memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
    // get destination IP address
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

    struct IP ip;
	strcpy(ip.src, inet_ntoa(source.sin_addr));  
	strcpy(ip.dst, inet_ntoa(dest.sin_addr));

	return ip;
}

// print useful data of tcp header
void print_tcp_header(const u_char * Buffer, int Size, struct tcphdr *tcph) {

	char buff [50];
    sprintf(buff, "   Src port: %d", ntohs(tcph->source));
	logger.log(buff);
    sprintf(buff, "   Dst port: %d", ntohs(tcph->dest));
	logger.log(buff);
}

// print useful data of udp header
void print_udp_header(const u_char *Buffer , int Size, struct udphdr *udph){

	char buff [50];
    sprintf(buff, "   Src port: %d", ntohs(udph->source));
	logger.log(buff);
    sprintf(buff, "   Dst port: %d", ntohs(udph->dest));
	logger.log(buff);
	
	if ( (ntohs(udph->source) == 53) || (ntohs(udph->dest) == 53))
		logger.log("        DNS: Yes");
	else
		logger.log("        DNS: No");	
}

// separate useful part of tcp packet
void Processing_tcp_packet(const u_char * Buffer, int Size, char* ip_protocol) {
    
    unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
			
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;


    // get printable part of payload
    char *printable_payload = find_printable_payload(Buffer + header_size, Size - header_size);

	// get ip from function
	struct IP ip = Processing_ip_header(Buffer, Size);

	logger.log(" ");
	packet_number ++;
	tcp_number ++;
	char buff [50];
    sprintf(buff, "     number: %d", packet_number);
	logger.log(buff);
    sprintf(buff, "   Protocol: %s", ip_protocol);
	logger.log(buff);
    sprintf(buff, "   Protocol: TCP");
	logger.log(buff);
	
	print_ip_header(Size, ip);
    	print_tcp_header(Buffer, Size, tcph);

	if (strstr(printable_payload, "HTTP") != NULL)
		logger.log("       HTTP: Yes");
	else 
		logger.log("       HTTP: No");

    //sprintf(buff, "    payload: %s", printable_payload);
	//logger.log(buff);
}

// separate useful part of udp packet
void Processing_udp_packet(const u_char * Buffer, int Size, char *ip_protocol){


	// read config file
	char buffer [1024];
	FILE *fp;
	fp = fopen ("config.json", "r");
	fread (buffer,1024, 1, fp);
	fclose (fp);

	struct json_object *parsed_json;	
	struct json_object *json_device;
    struct json_object *json_number;

    parsed_json = json_tokener_parse(buffer);

    json_object_object_get_ex (parsed_json, "json_device", &json_device);
    json_object_object_get_ex (parsed_json, "json_number", &json_number);


	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

	// get printable part of payload
	char *printable_payload = find_printable_payload(Buffer + header_size, Size - header_size);

	// get ip from function
	struct IP ip = Processing_ip_header(Buffer, Size);

	logger.log(" ");
	packet_number ++;
	udp_number ++;
	char buff [50];
    sprintf(buff, "     number: %d", packet_number);
	logger.log(buff);
    sprintf(buff, "   Protocol: %s", ip_protocol);
	logger.log(buff);
    sprintf(buff, "   Protocol: UDP");
	logger.log(buff);
	
	print_ip_header(Size, ip);
	print_udp_header(Buffer , Size, udph);

    //sprintf(buff, "    payload: %s", printable_payload);
	//logger.log(buff);
}

// the major part of the program that gets a packet and extract important data of it
void packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body)
{

  	// read config file
        char buffer [512];
        FILE *fp;
        fp = fopen ("config.json", "r");
        fread (buffer, 512, 1, fp);
        fclose (fp);

        struct json_object *parsed_json;
        struct json_object *json_tcp;
        struct json_object *json_udp;
		struct json_object *json_ipv4;
		struct json_object *json_ipv6;
		struct json_object *json_arp;

        parsed_json = json_tokener_parse(buffer);

        json_object_object_get_ex (parsed_json, "json_tcp", &json_tcp);
        json_object_object_get_ex (parsed_json, "json_udp", &json_udp);
		json_object_object_get_ex (parsed_json, "json_ipv4", &json_ipv4);
        json_object_object_get_ex (parsed_json, "json_ipv6", &json_ipv6);
        json_object_object_get_ex (parsed_json, "json_arp", &json_arp);

        char tcp_add [15];
        strcpy (tcp_add, json_object_get_string(json_tcp));
        char udp_add [15];
        strcpy (udp_add, json_object_get_string(json_udp));
		char ipv4_add [15];
        strcpy (ipv4_add, json_object_get_string(json_ipv4));
        char ipv6_add [15];
        strcpy (ipv6_add, json_object_get_string(json_ipv6));
		char arp_add [15];
        strcpy (arp_add, json_object_get_string(json_arp));

	// crate object from classes
	Protocol tcp;
	Protocol udp;
	Protocol ipv4;
	Protocol ipv6;
	Protocol arp;

	// fill classes with data of config files if they are enable
	if (strcmp(tcp_add, "disable") != 0){
		
		// read this protocol config file
		char buffer [512];
		FILE *fp;
		fp = fopen (tcp_add, "r");
		fread (buffer, 512, 1, fp);
		fclose (fp);

		struct json_object *parsed_json;
		struct json_object *json_tcpudp_10;

		parsed_json = json_tokener_parse(buffer);
		json_object_object_get_ex (parsed_json, "json_tcpudp_10", &json_tcpudp_10);

		tcp.setTcpudp_10 (json_object_get_int(json_tcpudp_10));
	}
	if (strcmp(udp_add, "disable") != 0){
		
		// read this protocol config file
		char buffer [512];
		FILE *fp;
		fp = fopen (udp_add, "r");
		fread (buffer, 512, 1, fp);
		fclose (fp);

		struct json_object *parsed_json;
		struct json_object *json_tcpudp_10;

		parsed_json = json_tokener_parse(buffer);
		json_object_object_get_ex (parsed_json, "json_tcpudp_10", &json_tcpudp_10);

		udp.setTcpudp_10 (json_object_get_int(json_tcpudp_10));

	}
	if (strcmp(ipv4_add, "disable") != 0){
		
		// read this protocol config file
		char buffer [512];
		FILE *fp;
		fp = fopen (ipv4_add, "r");
		fread (buffer, 512, 1, fp);
		fclose (fp);

		struct json_object *parsed_json;
		struct json_object *json_ip_13;
		struct json_object *json_ip_14;

		parsed_json = json_tokener_parse(buffer);
		json_object_object_get_ex (parsed_json, "json_ip_13", &json_ip_13);
		json_object_object_get_ex (parsed_json, "json_ip_14", &json_ip_14);		

		ipv4.setIp_13 (json_object_get_int(json_ip_13));
		ipv4.setIp_14 (json_object_get_int(json_ip_14));
	}
	if (strcmp(ipv6_add, "disable") != 0){
		
		// read this protocol config file
		char buffer [512];
		FILE *fp;
		fp = fopen (ipv6_add, "r");
		fread (buffer, 512, 1, fp);
		fclose (fp);

		struct json_object *parsed_json;
		struct json_object *json_ip_13;
		struct json_object *json_ip_14;

		parsed_json = json_tokener_parse(buffer);
		json_object_object_get_ex (parsed_json, "json_ip_13", &json_ip_13);
		json_object_object_get_ex (parsed_json, "json_ip_14", &json_ip_14);		

		ipv6.setIp_13 (json_object_get_int(json_ip_13));
		ipv6.setIp_14 (json_object_get_int(json_ip_14));

	}
	if (strcmp(arp_add, "disable") != 0){
		
		// read this protocol config file
		char buffer [512];
		FILE *fp;
		fp = fopen (arp_add, "r");
		fread (buffer, 512, 1, fp);
		fclose (fp);

		struct json_object *parsed_json;
		struct json_object *json_ip_13;
		struct json_object *json_ip_14;

		parsed_json = json_tokener_parse(buffer);
		json_object_object_get_ex (parsed_json, "json_ip_13", &json_ip_13);
		json_object_object_get_ex (parsed_json, "json_ip_14", &json_ip_14);		

		arp.setIp_13 (json_object_get_int(json_ip_13));
		arp.setIp_14 (json_object_get_int(json_ip_14));

	}

    u_char protocol_byte_13 = *(packet_body + 12);
	u_char protocol_byte_14 = *(packet_body + 13);

//	printf ("proto %d\t %d \n", protocol_byte_13, protocol_byte_14);	
//	printf ("ipv4 %d\t %d \n", ipv4.getIp_13(), ipv4.getIp_14());	
//	printf ("arp %d\t %d \n", arp.getIp_13(), arp.getIp_14());	

	char ip_protocol [10];

    if ((protocol_byte_13 == 8) && (ipv4.getIp_13() == 8) && (protocol_byte_14 == 0) && (ipv4.getIp_14() == 0)){  //ipv4 Protocol
		strcpy (ip_protocol, "IPv4");
		ipv4_number ++;
		//printf("ipv4 cap\n"); 

	}else if ((protocol_byte_13 == 134) && (ipv6.getIp_13() == 134) && (protocol_byte_14 == 221) && (ipv6.getIp_14() == 221)){  //ipv6 Protocol
		strcpy (ip_protocol, "IPv6");
		ipv6_number ++;		

	}else if ((protocol_byte_13 == 8) && (arp.getIp_13() == 8) && (protocol_byte_14 == 6) && (arp.getIp_14() == 6)){  //arp Protocol
		strcpy (ip_protocol, "ARP");
		arp_number ++;
		//printf("arp cap");	

	}else{
		return;
	}

    // Pointers to start point of header.
    const u_char *ip_header;

    // Header lengths in bytes
    int ethernet_header_length = 14; // Doesn't change

    //start of IP header
    ip_header = packet_body + ethernet_header_length;

    //Protocol is always the 10th byte of the IP header
    u_char protocol = *(ip_header + 9);

	int size = packet_header->len;

    if ((protocol == 6) && (tcp.getTcpudp_10() == 6))  //TCP Protocol
		Processing_tcp_packet(packet_body , size, ip_protocol);
    
	else if ((protocol == 17) && udp.getTcpudp_10() == 17) //UDP Protocol
		Processing_udp_packet(packet_body , size, ip_protocol);
	else
		return;
}

// show all available device and choose one of them to sniff
struct device select_device(int device_num){

    pcap_if_t *alldevsp , *device;
    //char devs[100][100];
	struct device devices [20];
	char *errbuf;
	int count = 1;
	int n;

	//get the list of available devices
    printf("Finding available devices ... ");
    if( pcap_findalldevs( &alldevsp , errbuf) )
    {
        //printf("Error finding devices : %s" , errbuf);
		logger.log("Error finding devices");
        exit(1);
    }
    printf("Done");
     
    //Print the available devices
    printf("\n\nAvailable Devices are :\n");
    for(device = alldevsp ; device != NULL ; device = device->next)
    {
        printf("%d. %s - %s\n" , count , device->name , device->description);
        if(device->name != NULL)
        {
			// save device name
            strcpy(devices[count].name , device->name);

			// save device ip
			for(pcap_addr_t *a=device->addresses; a!=NULL; a=a->next) {
            	if(a->addr->sa_family == AF_INET) 
            		strcpy(devices[count].ip , inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
        	}

        }
        count++;
    }
     

    printf("\nNumber of device you want to sniff : %d", device_num);

	// copy and return selected device
	struct device selected_device;
	strcpy(selected_device.name, devices[device_num].name);
	strcpy(selected_device.ip, devices[device_num].ip);

    return selected_device;

 }


// detect address class
char addres_class_detection(char ip_reference [20]){

	// copy ip to a variable. not to change the ip
	char ip [20];
	strcpy(ip, ip_reference);

	// get first part of ip
	char * class_pointer = strtok(ip, ".");

	// convert to integer
	int class_add = atoi(class_pointer);

	if (1 <= class_add && class_add <= 127)
		 return 'A';
	else if (128 <= class_add && class_add <= 191)
		 return 'B';
	else if (192 <= class_add && class_add <= 223)
		 return 'C';
	else if (224 <= class_add && class_add <= 239)
		 return 'D';		 
	else if (240 <= class_add && class_add <= 247)
		 return 'E';	 
}


// define handle global, to use it in sig_handler function
pcap_t *handle;

// time of each period of capturing
int capture_time;

// run this function after an specific time of capturing
void sig_handler(int signum){

	pcap_breakloop(handle);

	char buff [50];
	logger.log(" ");
    sprintf(buff, "number of packets in last %d seconds", capture_time);
	logger.log(buff);
    sprintf(buff, "        tcp: %d", tcp_number);
	logger.log(buff);
	sprintf(buff, "        udp: %d", udp_number);
	logger.log(buff);
 	sprintf(buff, "       IPv4: %d", ipv4_number);
	logger.log(buff);
	sprintf(buff, "       IPv6: %d", ipv6_number);
	logger.log(buff);
	sprintf(buff, "        arp: %d", arp_number);
	logger.log(buff);
	

	tcp_number = 0;
	udp_number = 0;
	packet_number = 0;
	ipv4_number = 0;
	ipv6_number = 0;
	arp_number = 0;

}


// the main function
int main() {

	printf("Packet Sniffer\n");
	printf("Mahdi Hejrati\n\n");

    struct device device; // device to sniff on
    //pcap_t *handle; // session handle
    char error_buffer[PCAP_ERRBUF_SIZE]; // error string
	// filter expression (second part of the following expression means to filter packet with body)
    //char filter_exp[] = "((tcp port 8765) or (udp port 53))and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";
	char filter_exp[] = "";
	struct bpf_program filter; // compiled filter
    bpf_u_int32 raw_mask; // subnet mask
	bpf_u_int32 ip; // ip
    struct in_addr addr;
	char *mask; // dot notation of the network mask
	char addres_class; // ip address class between A, B, C, ...
	struct pcap_pkthdr header; //header that pcap gives us
	const u_char *packet; // actual packet
	

	// read config file
	char buffer [512];
	FILE *fp;
	fp = fopen ("config.json", "r");
	fread (buffer, 512, 1, fp);
	fclose (fp);

	// declare struct to read json
	struct json_object *parsed_json;	
	struct json_object *json_device;
    struct json_object *json_number;
    struct json_object *json_time;
	struct json_object *json_log;

    parsed_json = json_tokener_parse(buffer);

  	json_object_object_get_ex (parsed_json, "json_device", &json_device);
    json_object_object_get_ex (parsed_json, "json_number", &json_number);
    json_object_object_get_ex (parsed_json, "json_time", &json_time);
    json_object_object_get_ex (parsed_json, "json_log", &json_log);

	int device_num; // device number to capture
       	device_num = json_object_get_int(json_device);
	int num_packets; // number of packets to capture 
        num_packets = json_object_get_int(json_number);
   	capture_time = json_object_get_int(json_time);	
	string log_type; // log level
		log_type = json_object_get_string(json_log);

	// set log level
	logger.setType(log_type);


	// select device
	device = select_device(device_num);

	// ask pcap for the network address and mask of the device
    if( pcap_lookupnet(device.name, &ip, &raw_mask, error_buffer) == -1){

        //printf("Couldn't read device %s information - %s\n", device.name, error_buffer);
		logger.log("Couldn't read selected device information");
    }
	
	// get the subnet mask in a human readable form
    addr.s_addr = raw_mask;
    mask = inet_ntoa(addr);

	addres_class = addres_class_detection (device.ip);

	// print device information
	printf("\nDevice info\n");
	printf("Name: %s\n", device.name);
	printf("IP: %s\n", device.ip);
	printf("Mask: %s\n" , mask);
	printf("Class: %c\n", addres_class);
	  
	printf("\nNumber of packets you want to capture: %d", num_packets);

	// open device in promiscuous mode
    handle = pcap_open_live(device.name, BUFSIZ, 1, 0, error_buffer);
    if (handle == NULL) {
		logger.log("Couldn't open selected device");
        return 1;
	}

	// compile the filter expression
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
		logger.log("Bad filter");
        return 1;
    }
	// apply the compiled filter
    if (pcap_setfilter(handle, &filter) == -1) {
		logger.log("Error setting filter");
        return 1;
    }

	// print capture info
	printf("\n\nStart sniffing...\n");
	printf("period time: %d\n\n", capture_time);


	while (1) {
		
		// here we set an alarm for an specific time and then sig_handler function run
		signal(SIGALRM, sig_handler);
		alarm(capture_time);

		// start sniffing
		pcap_loop(handle, num_packets, packet_handler, NULL);

	}


	// cleanup 
	pcap_freecode(&filter);
	pcap_close(handle);


    closelog();
    return 0;
}

