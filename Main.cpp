// include dependent classes
#include "Engine/Engine.h"
#include "Input/Input.h"
#include "Engine/Logger.h"


#include <locale>
#include <json-c/json.h>
#include "spdlog/spdlog.h"
#include <string>
#include <string.h>

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <arpa/inet.h> // for inet_ntoa()

#include<signal.h>
#include<unistd.h>

using namespace std;


// list of all enable protocols to check each packet with them
vector <Protocol> protocols;

// create global logger object to use it all over the program
// set default log level to info, until reading config file
Logger logger("info");

// create a buffer to make log with it using sprintf
char logBuffer [64];

// an struct to hold name and ip of packets
struct device {

    char name [20];
    char ip [16];
};


Engine* engine;


// the major part of the program that gets a packet and extract important data of it
void packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body) {

    // trace
    logger.log("new packet captured", "trace");

    // Engine engine(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body);
    engine->Run (args, packet_header, packet_body, protocols);

}


// show all available device and choose one of them to sniff
struct device select_device(int device_num){

    pcap_if_t *alldevsp , *device;
    //char devs[100][100];
    struct device devices [20];
    char *errbuf = NULL;
    int count = 1;
    //int n;

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
    else 
        return '-';
}


// define handle global, to use it in sig_handler function
pcap_t *handle;


// time of each period of capturing
int capture_time;


// run this function after an specific time of capturing
void sig_handler(int signum){

    pcap_breakloop(handle);

    engine->showStatistics(capture_time);

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
    //struct pcap_pkthdr header; //header that pcap gives us
    //const u_char *packet; // actual packet


    // read config file once and then make objects
    char buffer [512] = "";
    FILE *fp;
    fp = fopen ("config/config.json", "r");
    if (fp == NULL){
        logger.log("Error in opening config file", "error");
        return 1;
    }
    fread (buffer, 512, 1, fp);
    fclose (fp);


    // declare struct to read json
    struct json_object *parsed_json;
    parsed_json = json_tokener_parse(buffer);


    // read device number
    struct json_object *json_device; // struct to read json
    int device_num; // device number to capture
    json_object_object_get_ex (parsed_json, "json_device", &json_device);
    if (json_device == NULL){
        logger.log("Couldn't read device number from config,   default device : 1", "warn");
        device_num = 1;
    }else{
        device_num = json_object_get_int(json_device);
    }
    // select device
    device = select_device(device_num);

    // read number of packets
    struct json_object *json_number; // struct to read json
    int num_packets; // number of packets to capture
    json_object_object_get_ex (parsed_json, "json_number", &json_number);
    if (json_number == NULL){
        logger.log("Couldn't read number of packets from config,   default number : 100", "warn");
        num_packets = 100;
    }else{
        num_packets = json_object_get_int(json_number);
    }

    // read each capture time period
    struct json_object *json_time; // struct to read json
    json_object_object_get_ex (parsed_json, "json_time", &json_time);
    if (json_time == NULL){
        logger.log("Couldn't read each capture time period from config,   default time : 10 s", "warn");
        capture_time = 10;
    }else{
        capture_time = json_object_get_int(json_time);
    }

    // read log level
    struct json_object *json_log; // struct to read json
    string log_type; // log level
    json_object_object_get_ex (parsed_json, "json_log", &json_log);
    if (json_log == NULL){
        logger.log("Couldn't read log level from config,   default level : info", "warn");
        log_type = "info";
    }else{
        log_type = json_object_get_string(json_log);
    }
    // set log level
    logger.setConfigType(log_type);


    // read all config files and make object of "enable" protocols to analyze it
    json_object * json_config = json_tokener_parse(buffer);
    Input inputClass(log_type);
    inputClass.json_parse_config(json_config, protocols);


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

    engine = new Engine(logger.getConfigType());

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