
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <fstream>
#include <ctime>
#include <thread>
#include "test.h"
using namespace std;
#define DEVICE_SERIAL_NUMBER "../device_serial_number"
/*
int CheckID(unsigned char* id, size_t ilen){
    fstream fs(DEVICE_SERIAL_NUMBER);
    if (!fs) {
        printf("CheckID: open file: %s Failed!\n", DEVICE_SERIAL_NUMBER);
        return -1;
    }
    unsigned char sn[81];
    while (fs.peek() != EOF) {
        fs.getline(sn, 81);
//      cout<<sn<<endl;
        if(memcmp(id, sn, ilen) == 0){
            return 0;
        }
    }
    fs.close();
    return -1;
}
*/
void T::test(){
printf("haha\n");
}
int main(){
/*
	unsigned char* id = "xingyunhulian1";
	size_t len = strlen(id);
	if(CheckID(id, len) == 0) cout<<"succ"<<endl;
	else cout<<"fail"<<endl;

    struct tm time_2004;
    time_2004.tm_sec = 0;
    time_2004.tm_min = 0;
    time_2004.tm_hour = 0;
    time_2004.tm_mday = 1;
    time_2004.tm_mon = 1;
    time_2004.tm_year = 104;
    time_t mt_2004 = mktime(&time_2004);
	cout<<mt_2004<<endl;
*/
thread d;
d = thread(T::test);
d.join();

return 0;
}
