#include "Property.h"

#include <iostream> 
#include <vector> 
  
using namespace std; 


#ifndef PROTOCOL_H
#define PROTOCOL_H


// class protocol holds information of each protocol
class Protocol {

private:

    char name [10];
    char layer [15];
    int probability = 0; // percentage probability of this protocol 
    vector <Property> properties;

public:
    
    // getter
    char * getName();
    char * getLayer();
    int getProbability();
    vector <Property> getProperties();

    // setter
    void setName(char n []);
    void setLayer(const char l []);

    void increaseProbability(int prob);
    void addProperty(Property prop);

};


#endif