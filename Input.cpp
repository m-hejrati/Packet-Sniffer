#include "Input.h"

#include <json-c/json.h>
#include <string>
#include <string.h>

using namespace std;


Logger logger3;


// constructor of Engine class
Input::Input(string logType) {

    logger3.setConfigType(logType);
}

// parse config file and make object
void Input::json_parse_config (json_object * jobj, vector <Protocol> &protocols) {

    // ya C++ kheili cherte ya json-c, chand saate rooye copy kardan ye string az to json be vector moonadm. 
    // list of all protocol	
    char protocol_list [10][10];

    // check all the key/value of config file
    json_object_object_foreach(jobj, key, val) {

        string keylid = key;

        // fill protocols list
        if (keylid == "protocol_list"){

            json_object *jarray;
            jarray = json_object_object_get(jobj, key);

            int arraylen = json_object_array_length(jarray);
            json_object *jvalue;

            for (int i=0; i< arraylen; i++){
                jvalue = json_object_array_get_idx(jarray, i);

                sprintf(protocol_list[i], "%s", json_object_get_string(jvalue));			
            }


        // if key stars with "protocol_" means that is related to a protocol
        }else if (keylid.rfind("protocol_", 0) == 0) {

            // WASTED more than an hour, i dont understand why not next line work correctly.
            //string value = json_object_get_string(val);
            char value[20] = "";
            sprintf(value, "%s", json_object_get_string(val));

    
            // if the protocol is not disable, make an object and read its specific file
            if (strcmp(value, "disable") != 0) {

                Protocol prot;
                //prot.name = keylid.substr(9);

                // save protocol name 
                static int i = 0;
                prot.setName(protocol_list[i++]);

                char buffer[512] = "";
                FILE *fp;
                fp = fopen(value, "r");
                if (fp == NULL){
                    logger3.log("Error in opening config file", "error");
                    return;
                }
                fread(buffer, 512, 1, fp);
                fclose(fp);

                json_object *jobj = json_tokener_parse(buffer);
                enum json_type type;

                // read all the property saved in the file
                json_object_object_foreach(jobj, key, val) {

                    type = json_object_get_type(val);
                    if (type == json_type_array) {

                        // "headers" reserved for possible headers.
                        string keylid = key;
                        if (keylid != "headers"){

                            Property prop;

                            json_object *jarray;
                            jarray = json_object_object_get(jobj, key);

                            prop.setStart_byte (json_object_get_int( json_object_array_get_idx(jarray, 0)));
                            prop.setEnd_byte (json_object_get_int( json_object_array_get_idx(jarray, 1)));
                            prop.setConstraint (json_object_get_int( json_object_array_get_idx(jarray, 2)));
                            prop.setProbability_change (json_object_get_int( json_object_array_get_idx(jarray, 3)));

                            // add each property to property list of protocol
                            prot.addProperty(prop);
                        }

                    }else{
                        //if (key == "layer")
                        prot.setLayer(json_object_get_string(val));
                    }

                }
                // add new protocol to protocol list
                protocols.push_back(prot);
            }
        }
    }
}
