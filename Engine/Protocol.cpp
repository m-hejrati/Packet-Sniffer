#include "Property.h"
#include "Protocol.h"

#include <iostream> 
#include <vector> 
  
using namespace std; 


char name [10];
char layer [15];
int probability = 0; // percentage probability of this protocol 
vector <Property> properties;

char * Protocol::getName(){
    return name;
}

char * Protocol::getLayer(){
    return layer; 
}

int Protocol::getProbability(){
    return probability;
}

vector <Property> Protocol::getProperties(){
    return properties;
}


void Protocol::setName(char n []){
    sprintf(name, "%s", n);
}

void Protocol::setLayer(const char l []){
    sprintf(layer, "%s", l);
}


void Protocol::increaseProbability(int prob){
    probability += prob;
}

void Protocol::addProperty(Property prop){
    properties.push_back(prop);
}
