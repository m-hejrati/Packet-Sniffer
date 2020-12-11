#include "../Engine/Protocol.h"
#include "../Engine/Logger.h"

#include <json-c/json.h>

#include <string>
#include <string.h>

using namespace std;


#ifndef INPUT_H
#define INPUT_H


// this class get input data
class Input{

private:

    Logger logger3;

public:

    Input(string logType);
    void json_parse_config (json_object * jobj, vector <Protocol> &protocols);

};


#endif