#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#define LEN 16 // 128 bits

int getRandomNumber(int randomFrom, int randomEnd){
    unsigned char key;
    FILE* random = fopen("/dev/urandom", "r");
    fread(&key, sizeof(unsigned char), 1, random);
    fclose(random);
    int intrival = randomEnd - randomFrom + 1;
    intrival = key%intrival;
    return intrival + randomFrom;
}

void randomString(char *rstring, int len){
    int i;
    for (i = 0; i < len; i++)
    {
        rstring[i] = getRandomNumber(33, 126);
    }
    rstring[len] = '\0'.
}

