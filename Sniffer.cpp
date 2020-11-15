// include dependent classes
#include "Logger.h"
#include "Logger.cpp" // ?
#include "Property.h"
#include "Property.cpp" // ?
#include "Protocol.h"
#include "Protocol.cpp" // ?


#include <locale>
#include <json-c/json.h>
#include "spdlog/spdlog.h"
#include <string>
#include <string.h>

using namespace std;

#include <pcap.h>
#include <stdio.h>
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



// list of all enable protocols to check each packet with them
vector <Protocol> protocols;


// create global logger object to use it all over the program
// set default log level to info, until reading config file
Logger logger("info");


// create a buffer to make log with it using sprintf
char logBuffer [50];


// an struct to hold name and ip of packets
struct device {

    char name [20];
    char ip [16];
};


// number of captured packets
int packet_number = 0;
int tcp_number = 0;
int udp_number = 0;
int ipv4_number = 0;
int ipv6_number = 0;


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
	
    sprintf(logBuffer, "Packet size: %d bytes", Size);
	logger.log(logBuffer, "info");
    sprintf(logBuffer, "     Src IP: %s", ip.src);
	logger.log(logBuffer, "info");
    sprintf(logBuffer, "     Dst IP: %s", ip.dst);
	logger.log(logBuffer, "info");
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

    sprintf(logBuffer, "   Src port: %d", ntohs(tcph->source));
	logger.log(logBuffer, "info");
    sprintf(logBuffer, "   Dst port: %d", ntohs(tcph->dest));
	logger.log(logBuffer, "info");
}


// print useful data of udp header
void print_udp_header(const u_char *Buffer , int Size, struct udphdr *udph){

    sprintf(logBuffer, "   Src port: %d", ntohs(udph->source));
	logger.log(logBuffer, "info");
    sprintf(logBuffer, "   Dst port: %d", ntohs(udph->dest));
	logger.log(logBuffer, "info");
		
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

    //sprintf(logBuffer, "   Protocol: TCP");
	//logger.log(logBuffer, "info");
	
	print_ip_header(Size, ip);
    print_tcp_header(Buffer, Size, tcph);

    //sprintf(logBuffer, "    payload: %s", printable_payload);
	//logger.log(logBuffer, "info");
}


// separate useful part of udp packet
void Processing_udp_packet(const u_char * Buffer, int Size){

	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

	// get printable part of payload
	char *printable_payload = find_printable_payload(Buffer + header_size, Size - header_size);

	// get ip from function
	struct IP ip = Processing_ip_header(Buffer, Size);

    //sprintf(logBuffer, "   Protocol: UDP");
	//logger.log(logBuffer, "info");
	
	print_ip_header(Size, ip);
	print_udp_header(Buffer , Size, udph);

    //sprintf(logBuffer, "    payload: %s", printable_payload);
	//logger.log(logBuffer, "info");
}


// the major part of the program that gets a packet and extract important data of it
void packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body) {

    // Pointers to start point of header.
    const u_char *ip_header;

    // Header lengths in bytes
    int ethernet_header_length = 14; // Doesn't change

    //start of IP header
    ip_header = packet_body + ethernet_header_length;


    logger.log(" ", "info");
    sprintf(logBuffer, "     number: %d", ++packet_number);
    logger.log(logBuffer, "info");

	// select between tcp or udp for printing data
	int tcpORudp = 0;	

    //check each protocol
    for (Protocol protocol : protocols) {

        const u_char *check;

        //if (protocol.layer == "internet"){
		if (strcmp(protocol.getLayer() , "internet") == 0){
        	check = packet_body;
		
		}else if (strcmp(protocol.getLayer() , "transport") == 0){
        //}else if (protocol.layer == "transport"){
            check = ip_header;

        }else if (strcmp(protocol.getLayer() , "application") == 0)
			printf("comming soon...");


        // check all property and its constraint of protocol
        for (Property property : protocol.getProperties()) {

			// check packet size
	        if (property.getConstraint() == -2){

				// calculate size from specified bytes of packet
				int calculated_size = (*(check + property.getStart_byte() - 1)) * 256 + (*(check + property.getEnd_byte() - 1)) + 14; 
				int structure_size = packet_header->len;
				
				if (calculated_size == structure_size)
					protocol.increaseProbability (property.getProbability_change());
			}
             
			// for now we just check one byte and also two bytes of size
            if (property.getStart_byte() == property.getEnd_byte())
  				if (property.getConstraint() == *(check + property.getStart_byte() - 1))
                    protocol.increaseProbability (property.getProbability_change());

        }
  
    	sprintf(logBuffer, "%11s: %%%d", protocol.getName(), protocol.getProbability());
        logger.log(logBuffer, "info");
			
		
		// save protocol with more probability between tcp or udp, (considered that we always check tcp first)
		int tcp_probability = 0;
		if ((strcmp(protocol.getName() , "tcp") == 0) && (protocol.getProbability() >= 50)){
			tcp_probability = protocol.getProbability();
			tcpORudp = 1;
            tcp_number ++;

		}else if ((strcmp(protocol.getName() , "udp") == 0) && (protocol.getProbability() >= 50))
			if (protocol.getProbability() > tcp_probability){
				tcpORudp = 2;
                udp_number ++;
            }

        // increase number pf packet
        if ((strcmp(protocol.getName() , "ipv4") == 0) && (protocol.getProbability() >= 50))
            ipv4_number ++;
        if ((strcmp(protocol.getName() , "ipv6") == 0) && (protocol.getProbability() >= 50))
            ipv6_number ++;

    }

    // print important data of packet
    int size = packet_header->len;
    if (tcpORudp == 1)
        Processing_tcp_packet(packet_body , size);
    else if (tcpORudp == 2)
        Processing_tcp_packet(packet_body , size);
			

    // debug
    sprintf(logBuffer, "proto %d\t %d", *(packet_body + 12), *(packet_body + 13));
    logger.log(logBuffer, "debug");


    //debug
    sprintf(logBuffer, "struct_size: %d \t", packet_header->len);
    logger.log(logBuffer, "debug");


    //debug
    sprintf(logBuffer, "byte_size: %d \t %d ", *(ip_header + 2), *(ip_header + 3));
    logger.log(logBuffer, "debug");

}


// parse config file and make object
void json_parse_config (json_object * jobj) {

	// ya C++ kheili cherte ya json-c, chand saate rooye copy kardan ye string az to json be vector moonadm. 
	// list of all protocol	
	char protocol_list [10][10];

    // check all the key/value of config file
    json_object_object_foreach(jobj, key, val) {
        enum json_type type;
        type = json_object_get_type(val);

        string keylid = key;

        // fill protocols list
        if (keylid == "protocol_list"){

            json_object *jarray = jobj;
            jarray = json_object_object_get(jobj, key);

            int arraylen = json_object_array_length(jarray);
            json_object *jvalue;

            for (int i=0; i< arraylen; i++){
                jvalue = json_object_array_get_idx(jarray, i);

                sprintf(protocol_list[i], "%s", json_object_get_string(jvalue));			
            }


        // if key stars with "protocol_" means that is related to a protocol
        }else if (keylid.rfind("protocol_", 0) == 0) {

            // WASTED more than an hour, i dont understand why not next line work correctly.
            //string value = json_object_get_string(val);
            char value[20] = "";
            sprintf(value, "%s", json_object_get_string(val));

	
            // if the protocol is not disable, make an object and read its specific file
            if (strcmp(value, "disable") != 0) {

                Protocol prot;
                //prot.name = keylid.substr(9);

				// save protocol name 
				static int i = 0;
                prot.setName(protocol_list[i++]);

                char buffer[512] = "";
                FILE *fp;
                fp = fopen(value, "r");
                fread(buffer, 512, 1, fp);
                fclose(fp);

                json_object *jobj = json_tokener_parse(buffer);
                enum json_type type;

                // read all the property saved in the file
                json_object_object_foreach(jobj, key, val) {

		            type = json_object_get_type(val);
		            if (type == json_type_array) {

		                Property prop;

		                json_object *jarray = jobj;
		                jarray = json_object_object_get(jobj, key);

		                json_object *jvalue;
		                prop.setStart_byte (json_object_get_int( json_object_array_get_idx(jarray, 0)));
		                prop.setEnd_byte (json_object_get_int( json_object_array_get_idx(jarray, 1)));
		                prop.setConstraint (json_object_get_int( json_object_array_get_idx(jarray, 2)));
		                prop.setProbability_change (json_object_get_int( json_object_array_get_idx(jarray, 3)));

		                // add each property to property list of protocol
                        prot.addProperty(prop);

		            }else{
		                //if (key == "layer")
                        prot.setLayer(json_object_get_string(val));
		            }

                }
                // add new protocol to protocol list
                protocols.push_back(prot);
            }
        }
    }
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
    //printf("Finding available devices ... ");
    if (pcap_findalldevs (&alldevsp, errbuf)) {
        logger.log("Error finding devices", "error");
        exit(1);
    }
    //printf("Done");

    //Print the available devices
    //printf ("\n\nAvailable Devices are :\n");
    for (device = alldevsp ; device != NULL ; device = device->next) {
        //printf("%d. %s - %s\n" , count , device->name , device->description);
        if (device->name != NULL) {
            // save device name
            strcpy(devices[count].name , device->name);

            // save device ip
            for(pcap_addr_t *a=device->addresses; a!=NULL; a=a->next) {
                //if(a->addr->sa_family == AF_INET) ?
                if(a->addr->sa_family == 2)
                    strcpy(devices[count].ip , inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
            }

        }
        count++;
    }


    //printf("\nNumber of device you want to sniff : %d", device_num);

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

    // print number of captured packtet and its protocol
    // this part should rewrite whenever new protocol add to program
    logger.log(" ", "info");
    sprintf(logBuffer, "number of packets in last %d seconds: %d", capture_time, packet_number);
	logger.log(logBuffer, "info");
    sprintf(logBuffer, "        tcp: %d", tcp_number);
	logger.log(logBuffer, "info");
	sprintf(logBuffer, "        udp: %d", udp_number);
	logger.log(logBuffer, "info");
 	sprintf(logBuffer, "       IPv4: %d", ipv4_number);
	logger.log(logBuffer, "info");
	sprintf(logBuffer, "       IPv6: %d", ipv6_number);
	logger.log(logBuffer, "info");
    logger.log(" ", "info");

	packet_number = 0;
	tcp_number = 0;
	udp_number = 0;
	ipv4_number = 0;
	ipv6_number = 0;

    if (logger.getConfigType() == "debug" || logger.getConfigType() == "trace")
        spdlog::dump_backtrace();

}



// the main function
int main() {

    logger.log("      \"Packet Sniffer\"", "info");
    logger.log("       \"Mahdi Hejrati\"", "info");


    struct device device; // device to sniff on
    //char error_buffer[PCAP_ERRBUF_SIZE]; // error string ?
    char error_buffer[256]; // error string
    char filter_exp[] = "";
    struct bpf_program filter; // compiled filter
    bpf_u_int32 raw_mask; // subnet mask
    bpf_u_int32 ip; // ip
    struct in_addr addr;
    char *mask; // dot notation of the network mask
    char addres_class; // ip address class between A, B, C, ...
    struct pcap_pkthdr header; //header that pcap gives us
    const u_char *packet; // actual packet


    // read config file once and then make objects
    char buffer [512] = "";
    FILE *fp;
    fp = fopen ("config/config.json", "r");
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
    logger.setConfigType(log_type);


    // read all config files and make object of "enable" protocols to analyze it
    json_object * json_config = json_tokener_parse(buffer);
    json_parse_config(json_config);


    // select device
    device = select_device(device_num);

    // ask pcap for the network address and mask of the device
    if( pcap_lookupnet(device.name, &ip, &raw_mask, error_buffer) == -1)
        logger.log("Couldn't read selected device information", "error");

    // get the subnet mask in a human readable form
    addr.s_addr = raw_mask;
    mask = inet_ntoa(addr);

    addres_class = addres_class_detection (device.ip);

    // print device information
    logger.log(" ", "info");
    logger.log("       Device info", "info");
    sprintf(logBuffer, "        Name: %s", device.name);
    logger.log(logBuffer, "info");
    sprintf(logBuffer, "          IP: %s", device.ip);
    logger.log(logBuffer, "info");
    sprintf(logBuffer, "        Mask: %s" , mask);
    logger.log(logBuffer, "info");
    sprintf(logBuffer, "       Class: %c", addres_class);
    logger.log(logBuffer, "info");

    //printf("\nNumber of packets you want to capture: %d", num_packets);

    // open device in promiscuous mode
    handle = pcap_open_live(device.name, BUFSIZ, 1, 0, error_buffer);
    if (handle == NULL) {
        logger.log("Couldn't open selected device", "error");
        return 1;
    }

    // compile the filter expression
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        logger.log("Bad filter", "error");
        return 1;
    }
    // apply the compiled filter
    if (pcap_setfilter(handle, &filter) == -1) {
        logger.log("Error setting filter", "error");
        return 1;
    }

    // print capture info
    logger.log(" ", "info");
    logger.log(" Start sniffing...", "info");
    sprintf(logBuffer, " period time: %d second", capture_time);
    logger.log(logBuffer, "info");


    while (1) {

        // here we set an alarm for an specific time and then sig_handler function run
        //signal(SIGALRM, sig_handler); ?
        signal(14, sig_handler);
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