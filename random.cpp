/////////////////////////////////////////////////////////////
// random.cpp - implementation and test stub of random class

#include "random.h"


int Random::getRandomNumber(int randomFrom, int randomEnd){
    unsigned char key;
    FILE* random = fopen("/dev/urandom", "r");
    fread(&key, sizeof(unsigned char), 1, random);
    fclose(random);
    int intrival = randomEnd - randomFrom + 1;
    intrival = key%intrival;
    return intrival + randomFrom;
}

std::string Random::getRandomString(){
    std::string rst;
    for(int i = 0; i < _len; i++){
        rst.push_back(getRandomNumber(33, 126));
    }
    return rst;
}

std::string Random::getRandomString(int length){
    std::string rst;
    for(int i = 0; i < length; i++){
        rst.push_back(getRandomNumber(33, 126));
    }
    return rst;
}
#ifdef TEST_RANDOM
int main(){
    Random ran;
    std::cout << ran.getRandomNumber(0, 100) << std::endl;
    std::cout << ran.getRandomString() << std::endl;
    std::cout << ran.getRandomString(12) << std::endl;
    
    return 0;
}
#endif