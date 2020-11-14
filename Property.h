#ifndef PROPERTY_H
#define PROPERTY_H


// this class save properties of protocols
class Property{

private:

    int start_byte;
    int end_byte;
    int constraint;
    int probability_change;


public:

    // getter
    int getStart_byte();
    int getEnd_byte();
    int getConstraint();
    int getProbability_change();

    // setter
    void setStart_byte(int sByte);
    void setEnd_byte(int endB);
    void setConstraint(int cons);
    void setProbability_change(int prob);

};


#endif