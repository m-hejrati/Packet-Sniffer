#include "Property.h"


int start_byte;
int end_byte;
int constraint;
int probability_change;


int Property::getStart_byte(){
    return start_byte;
}

int Property::getEnd_byte(){
    return end_byte;
}

int Property::getConstraint(){
    return constraint;
}

int Property::getProbability_change(){
    return probability_change;
}

void Property::setStart_byte(int sByte){
    start_byte = sByte;
}

void Property::setEnd_byte(int endB){
    end_byte = endB;
}

void Property::setConstraint(int cons){
    constraint = cons;
}

void Property::setProbability_change(int prob){
    probability_change = prob;
}