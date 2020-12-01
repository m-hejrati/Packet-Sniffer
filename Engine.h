#include "Session.h"
#include "Protocol.h"
#include "Logger.h"


#include <string>
#include <string.h>
#include <vector>


using namespace std;


#ifndef ENGINE_H
#define ENGINE_H


// this class get a packet and do all processing on it
class Engine {

private:
    
    // list of all open sessions
    vector <Session> sessions;

    // create a buffer to make log with it using sprintf
    char logBuffer [64];

    // number of captured packets
    int packet_number = 0;
    int tcp_number = 0;
    int udp_number = 0;
    int ipv4_number = 0;
    int ipv6_number = 0;
    int dns_number = 0;
    int http_number = 0;

    Logger logger;


public:

    // an struct to hold source and destination of a packet 
    struct IP {

        char src [16];
        char dst [16];
    }ip;

    void showStatistics(int capture_time);

    // find and save prinatble part of payload
    char* find_printable_payload(const u_char *payload, int len);

    // separate useful part of ip header
    void Processing_ip_header(const u_char * Buffer, int Size);

    // separate useful part of tcp packet
    Session Processing_tcp_packet(const u_char * Buffer, int Size);

    // separate useful part of udp packet
    Session Processing_udp_packet(const u_char * Buffer, int Size);

    // save sessions 
    void processing_session(Session& newSession);

    // check protocol properties
    void check_properties(Protocol &protocol, const u_char *check, const struct pcap_pkthdr *packet_header);

    // constructor 
    Engine(string logType);

    // run the engine
    void Run(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body, vector <Protocol> protocols);


};


#endif