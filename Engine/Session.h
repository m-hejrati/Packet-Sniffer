#include "Logger.h"

#include <string>
#include <string.h>

using namespace std; 


#ifndef TEST_PEOTOCOL_H
#define TEST_PROTOCOL_H


// class sesssion holds information of each sessions
class Session {

private:

    string type;
    string srcIP;
    string dstIP;
    string scrPort;
    string dstPort;
    string status;
    int numbers;
    string serverName;


public:
    
    Session(string typ, string sIP, string dIP, string sPort, string dPort);

    // getter
    string getType();
    string getSrcIP();
    string getDstIP();
    string getSrcPort();
    string getDstPort();
    int getNumbers();
    string getServerName();

    // setter
    void setType(string typ);
    void setServerName(string server);

    // increase number of packet in this session
    void increaseNumbers(int a);
    
    // check if two packets are in the same session or not by checking five tuples
    bool checkSession(Session newSession);
    
    // check source and destenation of port and IP
    bool check4(Session newSession);
    
    // save information of this packet
    void logInfo(Logger logger);

};


#endif