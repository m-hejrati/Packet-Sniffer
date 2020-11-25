#include "Session.h"
#include "Logger.h"

#include <iostream>
#include <string>
#include <string.h>

//using namespace std; 


// // a five tuple to hold important data of session
// struct fiveTuple {

//     string type;
//     string srcIP;
//     string dstIP;
//     char * scrPort;
//     char * dstPort;
// };


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

// string Session::getStatus(){
//     return status;
// }

// int Session::getNumbers(){
//     return numbers;
// }

void Session::setType(string typ){
    type = typ;
}

// void Session::setSrcIP(string src){
//     srcIP = src;
// }

// void Session::setDstIP(string dst){
//     dstIP = dst;
// }

// void Session::setSrcPort(string src){
//     scrPort = src;
// }

// void Session::setDstPort(string dst){
//     dstPort = dst;
// }

// void Session::setStatus(string st){
//     status = st;
// }

void Session::increaseNumbers(){
    numbers ++;
}

bool Session::checkSession(Session newSession){
		
    if (type == newSession.getType()){

        if ((srcIP == newSession.getSrcIP()) && (dstIP == newSession.getDstIP()) && (scrPort == newSession.getSrcPort()) && (dstPort == newSession.getDstPort()))
            return true;

        if ((srcIP == newSession.getDstIP()) && (dstIP == newSession.getSrcIP()) && (scrPort == newSession.getDstPort()) && (dstPort == newSession.getSrcPort()))
            return true;

    }else
        return false;    
}


void Session::logInfo(Logger logger){

    //printf("%s", type);
    char logBuffer [256];
    // sprintf(logBuffer, "Protocol: %s  |  Src IP: %15s  |  Dst IP: %15s  |  Src port: %5s  |  Dst port: %5s", type.c_str(), srcIP.c_str(), dstIP.c_str(), scrPort.c_str(), dstPort.c_str());
    // logger.log(logBuffer, "info");
    sprintf(logBuffer, "Src IP: %15s  |  Dst IP: %15s  |  Src port: %5s  |  Dst port: %5s", srcIP.c_str(), dstIP.c_str(), scrPort.c_str(), dstPort.c_str());	
    logger.log(logBuffer, "info");

    //cout << type << srcIP << dstIP << scrPort << dstIP << "\n";

}