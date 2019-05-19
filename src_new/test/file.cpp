#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
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
#include <sstream>
using namespace std;
#define CRL_SERIAL_NUMBER "../serial_number/crl_serial_number"

unsigned long get_crl_serial_number(){
    unsigned long sn = 0;
    std::fstream fs;
    fs.open(CRL_SERIAL_NUMBER, ios::in);
    if (!fs) {
        printf("set_crl_serial_number: open file: %s Failed!\n", CRL_SERIAL_NUMBER);
        return 0;
    }
    std::string s;
    fs>>s;
    std::stringstream ss;
    ss<<s;
    ss>>sn;
    fs.close();
    return sn;
}

int set_crl_serial_number(unsigned long sn){
    std::fstream fs;
    fs.open(CRL_SERIAL_NUMBER, ios::out);
    if (!fs) {
        printf("set_crl_serial_number: open file: %s Failed!\n", CRL_SERIAL_NUMBER);
        return -1;
    }
    fs<<sn;
    fs.close();
}


int main(){
set_crl_serial_number(1000);
cout<<get_crl_serial_number()<<endl;
return 0;
}





