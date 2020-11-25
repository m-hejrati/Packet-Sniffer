#include "Logger.h"

#include <string>
#include <string.h>

using namespace std; 


// // a five tuple to hold important data of session
// struct fiveTuple {

//     string type;
//     string srcIP;
//     string dstIP;
//     char * scrPort;
//     char * dstPort;
// };


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


public:
    
    Session(string typ, string sIP, string dIP, string sPort, string dPort);

    // getter
    string getType();
    string getSrcIP();
    string getDstIP();
    string getSrcPort();
    string getDstPort();
    // string getStatus();
    // int getNumbers();

    // setter
    void setType(string typ);
    // void setSrcIP(string src);
    // void setDstIP(string dst);
    // void setSrcPort(string src);
    // void setDstPort(string dst);
    // void setStatus(string st);
    void increaseNumbers();
    bool checkSession(Session newSession);

    void logInfo(Logger logger);
};


#endif