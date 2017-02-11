#pragma once
/////////////////////////////////////////////////////////////
// random.h - implementation and test stub of random class //
// ver 1.0                                                 //
// Language:    C++                                        //
// Author: Cunyang Shui                                    //
/////////////////////////////////////////////////////////////
//
// class Random - generate random number and string
//
#include <iostream>

class Random{
public:
    Random(int len = 6) : _len(len){}
    ~Random(){}
    int getRandomNumber(int randomFrom, int randomEnd);
    std::string getRandomString();
    std::string getRandomString(int length);
private:
    int _len;
};
