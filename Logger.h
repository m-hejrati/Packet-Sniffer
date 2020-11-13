#include <string>
#include <string.h>

using namespace std;



#ifndef LOGGER_H
#define LOGGER_H


// this class log important event of the program
class Logger {

private:
    string configType; //log type that selected in config file

public:
    // setter
    void setConfigType(string t);

    // getter
    string getConfigType();

    // constructor of Logger class
    Logger(string typ);

    // get message and log with choose level
    // and log if selected level in config file is the same as log
    void log(string message, string logType);

};


#endif