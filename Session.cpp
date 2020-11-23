#include "Session.h"

#include <string>
#include <string.h>

using namespace std; 


string type;
string srcIP;
string dstIP;
string scrPort;
string dstPort;
string status;

string Session::getType(){
    return type;
}

string Session::getSrcIP(){
    return srcIP;
}

string Session::getDstIP(){
    return dstIP;
}

string Session::getSrcPort(){
    return scrPort;
}

string Session::getDstPort(){
    return dstPort;
}

string Session::getStatus(){
    return status;
}

void Session::setType(string typ){
    type = typ;
}

void Session::setSrcIP(string src){
    srcIP = src;
}

void Session::setDstIP(string dst){
    dstIP = dst;
}

void Session::setSrcPort(string src){
    scrPort = src;
}

void Session::setDstPort(string dst){
    dstPort = dst;
}

void Session::setStatus(string st){
    status = st;
}