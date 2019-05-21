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
using namespace std;
#define IP_HOST "172.17.118.9"
#define PORT 6666

int sock;
struct sockaddr_in addr;


int CreateSocket(const char* ip, uint16_t port){
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        printf("CreateSocket: socket() Failed!\n");
        return -1;
    }
    bzero(&addr,sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_port = htons(port); 

    return 0;
}

int SendMsg(void* msg, size_t mlen){
    if ((sendto(sock, msg, mlen, 0, (struct sockaddr *)&addr, sizeof(addr))) < 0){
        printf("SendMsg: Failed!\n");
        return -1;
    }
    return 0;
}

void* SendTest(){
   unsigned char test[10] = {0xff, 0xff, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0xff};
	size_t len = 10;
        while(true){
     if (SendMsg(test, len) != 0)
                {
                    printf("sendmsg Failed!\n");
                }
    printf("send: %d\n", len);
    for (int i = 0; i<len; i++) {
        printf("0x%02x ", *(test+i));
    }
    printf("\n");
sleep(1);
}
}

int main(){
     
   	pthread_t send;
     if(CreateSocket(IP_HOST, PORT) != 0){
		printf("CreatSocket Failed!\n");
		return 0;
	}
    pthread_create(&send, NULL, SendTest, NULL); 

    pthread_join(send, NULL);


}
