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
using namespace std;



int set_crl_serial_number(unsigned long sn){
    fstream fs;
    fs.open("/home/yzh/CA/ca/src_new/crls/crl_serial_number", ios::out);
    if (!fs) {
        printf("set_crl_serial_number: open file Failed!\n");
        return -1;
    }
    fs<<sn;
    fs.close();
}

int main(){
set_crl_serial_number(1000);

return 0;
}





