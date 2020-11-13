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
// and log if selected level in config file is the same as log
void Logger::log(string message, string logType){

    if (configType == "debug" && logType == "debug"){

        spdlog::debug(message);
        //spdlog::dump_backtrace(); // write this line when ever want to see dubug logs

    }else if (configType == "info" && logType == "info")

        spdlog::info(message);

    else if (configType == "warn" && logType == "warn")

        spdlog::warn(message);

    else if (configType == "error" && logType == "error")

        spdlog::error(message);

    else if (configType == "critical" && logType == "critical")

        spdlog::critical(message);
}
