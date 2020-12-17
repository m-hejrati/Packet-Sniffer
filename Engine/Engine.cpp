#include "Engine.h"

#include "spdlog/spdlog.h"

#include <string>
#include <string.h>
#include <vector>
#include <json-c/json.h>


#include <pcap.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>	//Provides declarations for icmp header
#include <netinet/udp.h>	//Provides declarations for udp header
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header


using namespace std;


// list of all open sessions
vector <Session> sessions;

// create a buffer to make log with it using sprintf
char logBuffer2 [64];

// number of captured packets
int packet_number = 0;
int tcp_number = 0;
int udp_number = 0;
int ipv4_number = 0;
int ipv6_number = 0;
int dns_number = 0;
int http_number = 0;
int https_number = 0;
unsigned int total_size = 0;

Logger logger2;

// an struct to hold source and destination of a packet 
struct IP {

    char src [16];
    char dst [16];
}ip;

char serverNameGlobal [64];

// constructor of Engine class
Engine::Engine(string logType) {

    logger2.setConfigType(logType);
}


void Engine::showStatistics(int capture_time){

    // print number of captured packtet and its protocol
    // this part should rewrite whenever new protocol add to program
    logger2.log(" ", "info");
    char buffer[256];

    if (total_size < 1000) 
        sprintf(buffer, "Total size of the packet passing through aparat = %.2f B", total_size);
    else if (total_size >= 1000 && total_size < 1000000)
        sprintf(buffer, "Total size of the packet passing through aparat = %.2f KB", total_size / 1024.0);
    else if (total_size >= 1000000)
        sprintf(buffer, "Total size of the packet passing through aparat = %.2f MB", total_size / 1048576.0);
    logger2.log(buffer, "info");

    sprintf(buffer, "Statistics of last %d seconds: packets: %d - sessions: %lu", capture_time, packet_number, sessions.size());
    logger2.log(buffer, "info");
    sprintf(buffer, " tcp: %3d   |    udp: %3d   |   ipv4: %3d   |   ipv6: %3d   |    dns: %3d   |   http: %3d   |   https: %3d", tcp_number, udp_number, ipv4_number, ipv6_number, dns_number, http_number, https_number), 
    logger2.log(buffer, "info");

	packet_number = 0;
	tcp_number = 0;
	udp_number = 0;
	ipv4_number = 0;
	ipv6_number = 0;
    dns_number = 0;
    http_number = 0;
    https_number = 0;
    total_size = 0;
    
    for(Session session : sessions)
        session.logInfo(logger2);
    logger2.log(" ", "info");

    sessions.clear();

    // show all saved log in last period of time again. (dar halat aadi log haye paiin tar az info ro neshoon nemide)
    // all: trace, debug, info, ... 
    if (logger2.getConfigType() == "debug" || logger2.getConfigType() == "trace")
        spdlog::dump_backtrace();

}


// find and save prinatble part of payload
char* Engine::find_printable_payload(const u_char *payload, int len){

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


// separate useful part of ip header
void Engine::Processing_ip_header(const u_char * Buffer, int Size) {

	struct sockaddr_in source,dest;
		
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	
	// get source IP address
    memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
    // get destination IP address
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

    // struct IP ip;
	strcpy(ip.src, inet_ntoa(source.sin_addr));  
	strcpy(ip.dst, inet_ntoa(dest.sin_addr));

	// return ip;
}


// separate useful part of tcp packet
Session Engine::Processing_tcp_packet(const u_char * Buffer, int Size) {
    
    // trace
    logger2.log("packet considered as tcp", "trace");

    
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	unsigned short iphdrlen = iph->ihl*4;
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

	// get ip from function
	// struct IP ip = Processing_ip_header(Buffer, Size);
	Processing_ip_header(Buffer, Size);
    
    // use two buffer to convert from uint16 to string
    char buf1 [10];
    sprintf(buf1, "%d", ntohs(tcph->source));
    char buf2 [10];
    sprintf(buf2, "%d", ntohs(tcph->dest));
    Session newSession("tcp", ip.src, ip.dst, buf1, buf2);
    return newSession;
}


// separate useful part of udp packet
Session Engine::Processing_udp_packet(const u_char * Buffer, int Size){

    // trace
    logger2.log("packet considered as udp", "trace");


	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	unsigned short iphdrlen = iph->ihl*4;
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));

	// get ip from function
	// struct IP ip = Processing_ip_header(Buffer, Size);	
    Processing_ip_header(Buffer, Size);

    // use two buffer to convert from uint16 to string
    char buf1 [10];
    sprintf(buf1, "%d", ntohs(udph->source));
    char buf2 [10];
    sprintf(buf2, "%d", ntohs(udph->dest));
    Session newSession("udp", ip.src, ip.dst, buf1, buf2);
    return newSession;    
}


// save sessions 
void Engine::processing_session(Session& newSession){

    // check all previous saved session to find the same
    bool newSessionFlag = true;
    for (Session& session : sessions) // use & for calling by reference
        if (session.check4(newSession)){
            newSession.increaseNumbers(session.getNumbers()); // chon newSession ro jadid sakhtim, pas # yarohash yeke. pas # ghabliaro aezafe mikonom behesh
            session.increaseNumbers(1);
            newSessionFlag = false;
            continue;
        }

    //make new session if not exist
    if (newSessionFlag){
        sessions.push_back(newSession);
    } 
}


// check protocol properties
void Engine::check_properties(Protocol &protocol, const u_char *check, const struct pcap_pkthdr *packet_header){

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
}


void Engine::Run(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body, vector <Protocol> protocols){

   // Pointers to start point of header.
    const u_char *ip_header;

    // Header lengths in bytes
    int ethernet_header_length = 14; // Doesn't change

    //start of IP header
    ip_header = packet_body + ethernet_header_length;


    // make an string to print probability of each protocol
    char probabilitiesBuffer [256] = "#";
    sprintf (probabilitiesBuffer + strlen(probabilitiesBuffer),"%03d =>", ++packet_number);


	// select between tcp or udp for printing data
	int tcpORudp = 0;	
    // a flag to show if we have application layer protocol or not 
    bool applicationLayerflag = false;
    // a pointer to first part that we want to check. it differ in protocols depend on their layer.
    const u_char *startCheckBit;

    //check each protocol
    for (Protocol protocol : protocols) {

        // trace
        sprintf(logBuffer2, "check packet structure with %s protocol", protocol.getName());
        logger2.log(logBuffer2, "trace");


        // check protocols of internet layer
		if (strcmp(protocol.getLayer() , "internet") == 0){
        	startCheckBit = packet_body;

            // check protocol properties
            check_properties(protocol, startCheckBit, packet_header);

            //debug
            sprintf(logBuffer2, "layer = %s, name = %s, prob = %d\n", protocol.getLayer(), protocol.getName(), protocol.getProbability());
            logger2.log(logBuffer2, "debug");

            // increase number pf packet
            if ((strcmp(protocol.getName() , "ipv4") == 0) && (protocol.getProbability() >= 50))
                ipv4_number ++;
            if ((strcmp(protocol.getName() , "ipv6") == 0) && (protocol.getProbability() >= 50))
                ipv6_number ++;
    
            // save probabilities
            sprintf (probabilitiesBuffer + strlen(probabilitiesBuffer),"%5s: %%%02d  |  ", protocol.getName(), protocol.getProbability());
		
        // check protocols of transport layer
        }else if (strcmp(protocol.getLayer() , "transport") == 0){
            startCheckBit = ip_header;

            // check protocol properties
            check_properties(protocol, startCheckBit, packet_header);

            //debug
            sprintf(logBuffer2, "layer = %s, name = %s, prob = %d\n", protocol.getLayer(), protocol.getName(), protocol.getProbability());
            logger2.log(logBuffer2, "debug");

            // save protocol with more probability between tcp or udp, (considered that we always check tcp first)
            int tcp_probability = 0;
            if ((strcmp(protocol.getName() , "tcp") == 0) && (protocol.getProbability() >= 50)){
                tcp_probability = protocol.getProbability();
                tcpORudp = 1;
            }else if ((strcmp(protocol.getName() , "udp") == 0) && (protocol.getProbability() >= 50))
                if (protocol.getProbability() > tcp_probability)
                    tcpORudp = 2;

            // save probabilities
            sprintf (probabilitiesBuffer + strlen(probabilitiesBuffer),"%5s: %%%02d  |  ", protocol.getName(), protocol.getProbability());

        // application layer check later
        }else if (strcmp(protocol.getLayer() , "application") == 0){
			applicationLayerflag = true;
        }
    }


    // Session* newSession = NULL;
    // get important data of packet
    int size = packet_header->len;
    if (tcpORudp == 1){

        tcp_number ++;
        // get 5 main part of packet and save them in an object of session class
        Session tmpSession = Processing_tcp_packet(packet_body , size);
        processing_session(tmpSession);
        //newSession = &session; 


        // find first byte of payload in tcp packet
        const u_char * buf = packet_body;              
        struct iphdr *iph = (struct iphdr *)( buf  + sizeof(struct ethhdr) );
        unsigned short iphdrlen = iph->ihl*4;
        struct tcphdr *tcph=(struct tcphdr*)(buf + iphdrlen + sizeof(struct ethhdr));
        int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
        startCheckBit = packet_body + header_size;


        // check application layer protocol
        if (applicationLayerflag)
            for (Protocol protocol : protocols)
                if (strcmp(protocol.getLayer() , "application") == 0){

                    // http is detected in different method than others...
                    if (strcmp(protocol.getName() , "http") == 0){
                        
                        // if it has payload ...
                        if (size > header_size){

                            // get printable part of payload
                            char *printable_payload = find_printable_payload(startCheckBit, size - header_size);

                            //printf("%s\n", printable_payload);

                            // check protocol properties
                            //check_properties(protocol, startCheckBit, packet_header);
                            // it should put in protocol class later
                            char buffer[512] = "";
                            FILE *fp;
                            fp = fopen("config/http.json", "r");
                            if (fp == NULL){
                                logger2.log("Error in opening config file", "error");
                                return;
                            }
                            fread(buffer, 512, 1, fp);
                            fclose(fp);

                            json_object *jobj = json_tokener_parse(buffer);
                            enum json_type type;

                            json_object_object_foreach(jobj, key, val) {

                                type = json_object_get_type(val);
                                if (type == json_type_array) {

                                    // "headers" reserved for possible headers
                                    string keylid = key;
                                    if (keylid == "headers"){

                                        json_object *jarray;
                                        jarray = json_object_object_get(jobj, key);

                                        int arraylen = json_object_array_length(jarray);
                                        json_object * jvalue;

                                        // get all headers and check if there is in http packet or not
                                        for (int i = 0; i < arraylen; i++){

                                            jvalue = json_object_array_get_idx(jarray, i);
                                            type = json_object_get_type(jvalue);
                                            string head = json_object_get_string(jvalue);

                                            if (strstr(printable_payload, head.c_str()) != NULL)
                                                protocol.increaseProbability(10);                                          
                                        }
                                    }
                                }
                            }                   
                        }

                    }else if (strcmp(protocol.getName() , "https") == 0){
                        
                        // check protocol properties
                        check_properties(protocol, startCheckBit, packet_header);

                        // find sni and save it to global variable if it is tls handshake (mikhastam too protocol save konam vali nashod)
                        if (protocol.getProbability() >= 50)
                            strcpy(serverNameGlobal, findSNI(startCheckBit, size - header_size));
                    }

                    // update protocol
                    updateApplicationProtocol(protocol, tmpSession);

                    // if this packet related to aparat.com
                    if(tmpSession.getServerName().find(".aparat.com") != std::string::npos){
                        total_size += size;
                    }

                    // save probabilities
                    sprintf (probabilitiesBuffer + strlen(probabilitiesBuffer),"%5s: %%%02d  |  ", protocol.getName(), protocol.getProbability());
                    
                    if((strcmp(protocol.getName() , "https") == 0) && ((protocol.getProbability() >= 50) || (tmpSession.getType() == "https")))
                        https_number ++;

                    if((strcmp(protocol.getName() , "http") == 0) && ((protocol.getProbability() >= 50) || (tmpSession.getType() == "http")))
                        http_number ++;
                }


        // log probabilities
        logger2.log(probabilitiesBuffer, "info");
        tmpSession.logInfo(logger2);


    }else if (tcpORudp == 2){

        udp_number ++;
        // get 5 main part of packet and save them in an object of session class
        Session tmpSession = Processing_udp_packet(packet_body , size);
        processing_session(tmpSession);
        //newSession = &session;


        // find first byte of payload in udp packet
        const u_char * buf = packet_body;              
        struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
        unsigned short iphdrlen = iph->ihl*4;
        struct udphdr *udph = (struct udphdr*)(buf + iphdrlen  + sizeof(struct ethhdr));
        int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
        startCheckBit = packet_body + header_size;
        
             
        // check application layer protocol
        if (applicationLayerflag)
            for (Protocol protocol : protocols)
                // if (strcmp(protocol.getLayer() , "application") == 0){
                // for now we just check dns packets
                if (strcmp(protocol.getName() , "dns") == 0){

                    // if it has payload ...
                    if(startCheckBit < packet_body + size - 10){ // 10 faghat baraye etminane bishtare
                                        
                        // check protocol properties
                        check_properties(protocol, startCheckBit, packet_header);

                        // update protocol
                        updateApplicationProtocol(protocol, tmpSession);
                    }

                    // save probabilities
                    sprintf (probabilitiesBuffer + strlen(probabilitiesBuffer),"%5s: %%%02d  |  ", protocol.getName(), protocol.getProbability());
                    
                    if((strcmp(protocol.getName() , "dns") == 0) && ((protocol.getProbability() >= 50) || (tmpSession.getType() == "dns")))
                        dns_number ++;
                
                }

        // log probabilities
        logger2.log(probabilitiesBuffer, "info");
        tmpSession.logInfo(logger2);
    }


    //debug
    sprintf(logBuffer2, "proto %d\t %d", *(packet_body + 12), *(packet_body + 13));
    logger2.log(logBuffer2, "debug");


    //debug
    sprintf(logBuffer2, "struct_size: %d \t", packet_header->len);
    logger2.log(logBuffer2, "debug");


    //debug
    sprintf(logBuffer2, "byte_size: %d \t %d ", *(ip_header + 2), *(ip_header + 3));
    logger2.log(logBuffer2, "debug");
}


// update session name if there is the same one before, or set protocol name to its session (in yaroo asl amaliat marboot be application layer e, etelaat bishtar dar gozaresh)
void Engine::updateApplicationProtocol(Protocol& protocol, Session& tmpSession){

    if (protocol.getProbability() >= 50){
        // check all previous saved session to find the same and update its type to new protocol in application layer
        for (Session& session : sessions){
            if (session.check4(tmpSession)){
                session.setType(protocol.getName());
                tmpSession.setType(protocol.getName());

                // save server name 
                if (strcmp(protocol.getName() , "https") == 0){
                    session.setServerName(serverNameGlobal);
                    tmpSession.setServerName(serverNameGlobal);
                }

                continue;
            }
        }


    }else{
        // set the packet protocol to its session packet
        for (Session session : sessions)
            if (session.check4(tmpSession))
                if (session.getType() == protocol.getName()){
                    tmpSession.setType(session.getType());
                    // save server name 
                    tmpSession.setServerName(session.getServerName());
                }
    }
}


// find server name in client hello message
char * Engine::findSNI(const u_char *check, int len){

    // find and save length of all variable parameter
    // to finally detect server name

    int sessionIDLength = * (check + 43);

    int startCipherSuitesLength = *(check + sessionIDLength + 44);
    int endCipherSuitesLength = *(check + sessionIDLength + 45);
    int CipherSuitesLength = 256 * startCipherSuitesLength + endCipherSuitesLength;

    int startServerNameLength = *(check + sessionIDLength + CipherSuitesLength + 57);
    int endServerNameLength = *(check + sessionIDLength + CipherSuitesLength + 58);
    int serverNameLength = 256 * startServerNameLength + endServerNameLength;

    // pointer to first byte of server name
    const u_char *startServerName = check + 59 + sessionIDLength + CipherSuitesLength;

    // save server name and return it from function
    char serverName [64]{};
    for(int i = 0 ; i < serverNameLength; i++)
        sprintf(serverName + strlen(serverName), "%c", *(startServerName + i));
   
    char * tmp = serverName;
    return tmp;
}
