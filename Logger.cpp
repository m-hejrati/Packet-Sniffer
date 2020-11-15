#include "Logger.h"
#include "spdlog/spdlog.h"
#include <string>
#include <string.h>

//using namespace std;


string configType;

// setter
void Logger::setConfigType(string t) {
    configType = t;
}

// getter
string Logger::getConfigType() {
    return configType;
}

// constructor of Logger class
Logger::Logger(string typ){
    configType = typ;
    spdlog::enable_backtrace(64);
}

// get message and log with choose level
// log all the message with the same and also higher priority than what saved in config file
void Logger::log(string message, string logType){

    //spdlog::dump_backtrace(); // write this line when ever want to see dubug logs

    if (configType == "trace"){
        
        if (logType == "trace")
            spdlog::trace(message);
        else if (logType == "debug")
            spdlog::debug(message);
        else if (logType == "info")
            spdlog::info(message);
        else if (logType == "warn")
            spdlog::warn(message);              
        else if (logType == "error")
            spdlog::error(message);
        else if (logType == "critical")
            spdlog::critical(message); 

    } else if (configType == "debug"){

        if (logType == "debug")
            spdlog::debug(message);
        else if (logType == "info")
            spdlog::info(message);
        else if (logType == "warn")
            spdlog::warn(message);              
        else if (logType == "error")
            spdlog::error(message);
        else if (logType == "critical")
            spdlog::critical(message); 

    }else if (configType == "info"){

        if (logType == "info")
            spdlog::info(message);
        else if (logType == "warn")
            spdlog::warn(message);              
        else if (logType == "error")
            spdlog::error(message);
        else if (logType == "critical")
            spdlog::critical(message); 

    }else if (configType == "warn"){

        if (logType == "warn")
            spdlog::warn(message);              
        else if (logType == "error")
            spdlog::error(message);
        else if (logType == "critical")
            spdlog::critical(message); 

    }else if (configType == "error"){

        if (logType == "error")
            spdlog::error(message);
        else if (logType == "critical")
            spdlog::critical(message); 

    }else if (configType == "critical"){

        if (logType == "critical")
            spdlog::critical(message); 
    }
}