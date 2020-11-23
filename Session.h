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

public:
    
    // getter
    string getType();
    string getSrcIP();
    string getDstIP();
    string getSrcPort();
    string getDstPort();
    string getStatus();

    // setter
    void setType(string typ);
    void setSrcIP(string src);
    void setDstIP(string dst);
    void setSrcPort(string src);
    void setDstPort(string dst);
    void setStatus(string st);

};


#endif