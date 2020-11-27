#include "Session.h"
#include "Logger.h"

#include <iostream>
#include <string>
#include <string.h>

//using namespace std; 


string type;
string srcIP;
string dstIP;
string scrPort;
string dstPort;
string status;
int numbers;


// constructor of Logger class
Session::Session(string typ, string sIP, string dIP, string sPort, string dPort){

    type = typ;
    srcIP = sIP;
    dstIP = dIP;
    scrPort = sPort;
    dstPort = dPort;
    status = "open";
    numbers = 1;
}

//getter

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

int Session::getNumbers(){
    return numbers;
}


//setter

void Session::setType(string typ){
    type = typ;
}


// increase number of packet in this session
void Session::increaseNumbers(int a){
    numbers += a;
}


// check if two packets are in the same session or not by checking five tuples
bool Session::checkSession(Session newSession){
		
    if (type == newSession.getType())
        if (this->check4(newSession))
            return true;

    return false;    
}


// check source and destenation of port and IP
bool Session::check4(Session newSession){

    if ((srcIP == newSession.getSrcIP()) && (dstIP == newSession.getDstIP()) && (scrPort == newSession.getSrcPort()) && (dstPort == newSession.getDstPort()))
        return true;

    if ((srcIP == newSession.getDstIP()) && (dstIP == newSession.getSrcIP()) && (scrPort == newSession.getDstPort()) && (dstPort == newSession.getSrcPort()))
        return true;

    return false;    
}


// save information of this packet
void Session::logInfo(Logger logger){

    char logBuffer [256];
    sprintf(logBuffer, "Protocol: %4s  |  Src IP: %15s  |  Dst IP: %15s  |  Src port: %5s  |  Dst port: %5s  |  #%02d", type.c_str(), srcIP.c_str(), dstIP.c_str(), scrPort.c_str(), dstPort.c_str(), numbers);
    logger.log(logBuffer, "info");
}