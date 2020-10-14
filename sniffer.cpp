#include <locale>
#include <json-c/json.h>

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


// a class to save protocol feature
class Protocol{

public:
	int tcpudp = 0;
};

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

// number of captured packets
int packet_number = 0;

// an struct to save information of each session
struct session_info {
	int No;
	char type [4];
	char src_IP[16];
	char dst_IP[16];
	long scr_port;
	long dst_port;
	int num_req;
	int num_rsp;
	long len;
	int status;
};

// an array of session_info structure
struct session_info session[1000];
int z = 0;

// an struct save number of each protocol 
struct packet_protocol {

	int FTP_DATA;
	int FTP;
	int SSH;
	int TELNET;
	int SMTP;
	int DNS;
	int TFTP;
	int HTTP;
	int POP3;
	int NNTP;
	int NTP;
	int IMAP4;
	int HTTPS;
	int Others;

};

struct packet_protocol protocols;

// set number of different protocol to zero
void reset_protocols (){

	protocols.FTP_DATA = 0;
	protocols.FTP = 0;
	protocols.SSH = 0;
	protocols.TELNET = 0;
	protocols.SMTP = 0;
	protocols.DNS = 0;
	protocols.TFTP = 0;
	protocols.HTTP = 0;
	protocols.POP3 = 0;
	protocols.NNTP = 0;
	protocols.NTP = 0;
	protocols.IMAP4 = 0;
	protocols.HTTPS = 0;
	protocols.Others = 0;

}

// add protocol of captured packet to list
void save_protocol(int src_port, int dst_port){

	switch (src_port) {
		case 20:
			protocols.FTP_DATA ++;
			return;
		case 21:
			protocols.FTP ++;
			return;
		case 22:
			protocols.SSH ++;
			return;
		case 23:
			protocols.TELNET ++;
			return;
		case 25:
			protocols.SMTP ++;
			return;
		case 53:
			protocols.DNS ++;
			return;
		case 69:
			protocols.TFTP ++;
			return;
		case 80:
			protocols.HTTP ++;
			return;
		case 110:
			protocols.POP3 ++;
			return;
		case 119:
			protocols.NNTP ++;
			return;
		case 123:
			protocols.NTP ++;
			return;
		case 143:
			protocols.IMAP4 ++;
			return;
		case 443:
			protocols.HTTPS ++;
			return;
		default:
			// pass			
			break;
	}
	
	switch (dst_port) {
		case 20:
			protocols.FTP_DATA ++;
			return;
		case 21:
			protocols.FTP ++;
			return;
		case 22:
			protocols.SSH ++;
			return;
		case 23:
			protocols.TELNET ++;
			return;
		case 25:
			protocols.SMTP ++;
			return;
		case 53:
			protocols.DNS ++;
			return;
		case 69:
			protocols.TFTP ++;
			return;
		case 80:
			protocols.HTTP ++;
			return;
		case 110:
			protocols.POP3 ++;
			return;
		case 119:
			protocols.NNTP ++;
			return;
		case 123:
			protocols.NTP ++;
			return;
		case 143:
			protocols.IMAP4 ++;
			return;
		case 443:
			protocols.HTTPS ++;
			return;
		default:
			protocols.Others ++;			
			return;
	}
}

// save session information
void save_session(char type[], struct IP ip, int src_port, int dst_port, int Size, int fin){

	int flag = 1;

	for (int i = 0; i < z; i++){
		
		if (strcmp(session[i].type, type) == 0)

			if ( (strcmp(session[i].src_IP, ip.src) == 0) && (strcmp(session[i].dst_IP, ip.dst) == 0) && (session[i].scr_port == src_port) && (session[i].dst_port == dst_port) ){
				
				session[i].num_req ++;
				session[i].len += Size;
				flag = 0;
				session[i].status = fin;
				break;

			} else if ( (strcmp(session[i].src_IP, ip.dst) == 0) && (strcmp(session[i].dst_IP, ip.src) == 0) && (session[i].scr_port == dst_port) && (session[i].dst_port == src_port) ){

				session[i].num_rsp ++;
				session[i].len += Size;
				flag = 0;
				session[i].status = fin;
				break;

			}
	}

	// if there is not any similiar session
	if (flag){
		
		session[z].No = z+1;
		strcpy(session[z].type, type);
		strcpy(session[z].src_IP, ip.src);
		strcpy(session[z].dst_IP, ip.dst);
		session[z].scr_port = src_port;
		session[z].dst_port = dst_port;
		session[z].num_req = 1;
		session[z].num_rsp = 0;
		session[z].len = Size;
		session[z].status = fin;
		z++;
	}

}

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
	
    syslog(LOG_INFO, "Packet size: %d bytes\n", Size);
	syslog(LOG_INFO, "     Src IP: %s\n", ip.src);
	syslog(LOG_INFO, "     Dst IP: %s\n", ip.dst);
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

    syslog(LOG_INFO, "   Src port: %d\n", ntohs(tcph->source));
	syslog(LOG_INFO, "   Dst port: %d\n", ntohs(tcph->dest));
	
}

// print useful data of udp header
void print_udp_header(const u_char *Buffer , int Size, struct udphdr *udph){

    syslog(LOG_INFO, "   Src port: %d\n", ntohs(udph->source));
	syslog(LOG_INFO, "   Dst port: %d\n", ntohs(udph->dest));
	
	if ( (ntohs(udph->source) == 53) || (ntohs(udph->dest) == 53))
		syslog(LOG_INFO, "        DNS: Yes\n");
	else
		syslog(LOG_INFO, "        DNS: No\n");	
}

// separate useful part of tcp packet
void Processing_tcp_packet(const u_char * Buffer, int Size) {
    
    unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
			
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;


    // get printable part of payload
    char *printable_payload = find_printable_payload(Buffer + header_size, Size - header_size);

	// get ip from function
	struct IP ip = Processing_ip_header(Buffer, Size);

	syslog(LOG_INFO, " ");
	packet_number ++;
	syslog(LOG_INFO, "     number: %d", packet_number);
	syslog(LOG_INFO, "   Protocol: TCP\n");
	
	print_ip_header(Size, ip);
    	print_tcp_header(Buffer, Size, tcph);

	if (strstr(printable_payload, "HTTP") != NULL)
		syslog(LOG_INFO, "       HTTP: Yes\n");
	else 
		syslog(LOG_INFO, "       HTTP: No\n");

	syslog(LOG_INFO, "    payload: %s", printable_payload);

	printf("%d) TCP packet logged\n", packet_number);

	save_session("tcp", ip, ntohs(tcph->source), ntohs(tcph->dest), Size, (int)tcph->fin);
	save_protocol(ntohs(tcph->source), ntohs(tcph->dest));
}

// separate useful part of udp packet
void Processing_udp_packet(const u_char * Buffer, int Size){


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

	syslog(LOG_INFO, " ");
	packet_number ++;
	syslog(LOG_INFO, "     number: %d", packet_number);
	syslog(LOG_INFO, "   Protocol: UDP\n");
	
	print_ip_header(Size, ip);
	print_udp_header(Buffer , Size, udph);
	syslog(LOG_INFO, "    payload: %s", printable_payload);

	printf("%d) UDP packet logged\n", packet_number);

	save_session("udp", ip, ntohs(udph->source), ntohs(udph->dest), Size, 0);
	save_protocol(ntohs(udph->source), ntohs(udph->dest));

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

        parsed_json = json_tokener_parse(buffer);

        json_object_object_get_ex (parsed_json, "json_tcp", &json_tcp);
        json_object_object_get_ex (parsed_json, "json_udp", &json_udp);

        char tcp_add [10];
        strcpy (tcp_add, json_object_get_string(json_tcp));
        char udp_add [10];
        strcpy (udp_add, json_object_get_string(json_udp));

	// crate object from classes
	Protocol tcp;
	Protocol udp;

	// fill classes with data of config files if they are enable
	if (strcmp(tcp_add, "disable") != 0){
		
		// read this protocol config file
		char buffer [512];
		FILE *fp;
		fp = fopen (tcp_add, "r");
		fread (buffer, 512, 1, fp);
		fclose (fp);

		struct json_object *parsed_json;
		struct json_object *json_tcpudp;

		parsed_json = json_tokener_parse(buffer);
		json_object_object_get_ex (parsed_json, "json_tcpudp", &json_tcpudp);

		tcp.tcpudp = json_object_get_int(json_tcpudp);
	}
	if (strcmp(udp_add, "disable") != 0){
		
		// read this protocol config file
		char buffer [512];
		FILE *fp;
		fp = fopen (udp_add, "r");
		fread (buffer, 512, 1, fp);
		fclose (fp);

		struct json_object *parsed_json;
		struct json_object *json_tcpudp;

		parsed_json = json_tokener_parse(buffer);
		json_object_object_get_ex (parsed_json, "json_tcpudp", &json_tcpudp);

		udp.tcpudp = json_object_get_int(json_tcpudp);

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

    	if ((protocol == 6) && (tcp.tcpudp == 6))  //TCP Protocol
		Processing_tcp_packet(packet_body , size);
    
	else if ((protocol == 17) && udp.tcpudp == 17) //UDP Protocol
		Processing_udp_packet(packet_body , size);
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
        printf("Error finding devices : %s" , errbuf);
		syslog(LOG_ERR, "Error finding devices : %s" , errbuf);
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

// write a flag to save number of each protocol every minutes instead of 30 second.
int one_minute_flag = 0;

// run this function after 30 second of capturing
void sig_handler(int signum){

	pcap_breakloop(handle);

	if (z != 0){

		printf("%d packet in %d session recorded in last 30 seconds \n", packet_number, z);
		syslog(LOG_INFO, " ");
		syslog(LOG_INFO, "%d session recorded in last 30 seconds \n", z);

		for(int i = 0; i < z; i++){

			syslog(LOG_INFO, " ");
			syslog(LOG_INFO, "Session No: %d", i+1);
			syslog(LOG_INFO, "  Protocol: %s", session[i].type);
			syslog(LOG_INFO, "    Src IP: %s", session[i].src_IP);
			syslog(LOG_INFO, "    Dst IP: %s", session[i].dst_IP);
			syslog(LOG_INFO, "  Src port: %ld", session[i].scr_port);
			syslog(LOG_INFO, "  Dst port: %ld", session[i].dst_port);
			syslog(LOG_INFO, "      Sent: %d", session[i].num_req);
			syslog(LOG_INFO, "  Received: %d", session[i].num_rsp);
			syslog(LOG_INFO, "Total Size: %ld", session[i].len);
			if (strcmp(session[i].type, "tcp") == 0)
				if(session[i].status)
					syslog(LOG_INFO, "    Status: close");
				else 
					syslog(LOG_INFO, "    Status: open");
		}
	
		z = 0;
		packet_number = 0;		

	}else{
		syslog(LOG_INFO, " ");
		syslog(LOG_INFO, "No packet captured in last 30 seconds \n");
		printf("No packet captured in last 30 seconds \n");	
	}

	// save number of each protocol every minutes
	if (one_minute_flag){

	syslog(LOG_DEBUG, "\n");
	syslog(LOG_DEBUG, "Number of packets from each type of protocol in last one minute:\n");
	
	syslog(LOG_DEBUG, "  FTP_DATA: %d\n", protocols.FTP_DATA);
	syslog(LOG_DEBUG, "       FTP: %d\n", protocols.FTP);
	syslog(LOG_DEBUG, "       SSH: %d\n", protocols.SSH);
	syslog(LOG_DEBUG, "    TELNET: %d\n", protocols.TELNET);
	syslog(LOG_DEBUG, "      SMTP: %d\n", protocols.SMTP);
	syslog(LOG_DEBUG, "       DNS: %d\n", protocols.DNS);
	syslog(LOG_DEBUG, "      TFTP: %d\n", protocols.TFTP);
	syslog(LOG_DEBUG, "      HTTP: %d\n", protocols.HTTP);
	syslog(LOG_DEBUG, "      POP3: %d\n", protocols.POP3);
	syslog(LOG_DEBUG, "      NNTP: %d\n", protocols.NNTP);
	syslog(LOG_DEBUG, "       NTP: %d\n", protocols.NTP);
	syslog(LOG_DEBUG, "     IMAP4: %d\n", protocols.IMAP4);
	syslog(LOG_DEBUG, "     HTTPS: %d\n", protocols.HTTPS);
	syslog(LOG_DEBUG, "    Others: %d\n", protocols.Others);
	printf("protocols in last one minute logged \n");

	reset_protocols();

	one_minute_flag = 0;

	}else{
		one_minute_flag = 1;	
	}

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
	
	reset_protocols();

	// open logging machine
	openlog("p2-advanced | sniffer", LOG_PID, LOG_USER);


	// read config file
	char buffer [512];
	FILE *fp;
	fp = fopen ("config.json", "r");
	fread (buffer, 512, 1, fp);
	fclose (fp);

	struct json_object *parsed_json;	
	struct json_object *json_device;
        struct json_object *json_number;

        parsed_json = json_tokener_parse(buffer);

        json_object_object_get_ex (parsed_json, "json_device", &json_device);
        json_object_object_get_ex (parsed_json, "json_number", &json_number);

	int device_num; // device number to capture
       	device_num = json_object_get_int(json_device);
	int num_packets; // number of packets to capture 
        num_packets = json_object_get_int(json_number);


	// select device
	device = select_device(device_num);

	// ask pcap for the network address and mask of the device
    if( pcap_lookupnet(device.name, &ip, &raw_mask, error_buffer) == -1){

        printf("Couldn't read device %s information - %s\n", device.name, error_buffer);
		syslog(LOG_ERR, "Couldn't read device %s information - %s\n", device.name, error_buffer);
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
        printf("Couldn't open device %s - %s\n", device.name, error_buffer);
		syslog(LOG_ERR, "Couldn't open device %s - %s\n", device.name, error_buffer);
        return 1;
	}

	// compile the filter expression
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
		syslog(LOG_ERR, "Bad filter - %s\n", pcap_geterr(handle));
        return 1;
    }
	// apply the compiled filter
    if (pcap_setfilter(handle, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
		syslog(LOG_ERR, "Error setting filter - %s\n", pcap_geterr(handle));
        return 1;
    }

	// print capture info
	printf("\nStart sniffing...\n\n");
	printf("Number of packets: %d\n\n", num_packets);
    syslog(LOG_INFO, "Start sniffing on device: %s and %d packets", device.name, num_packets);

	while (1) {

		signal(SIGALRM, sig_handler);
		alarm(30);

		// start sniffing
		pcap_loop(handle, num_packets, packet_handler, NULL);

	}

	// cleanup 
	pcap_freecode(&filter);
	pcap_close(handle);


    closelog();
    return 0;
}

