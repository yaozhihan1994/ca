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
#define IP_HOST "127.0.0.1"
#define PORT 6666

int sock_r, sock_s;
struct sockaddr_in addr_r, addr_s;
int CreateSocket(const char* ip, uint16_t port){
    
    if ((sock_r = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        printf("CreateSocket: socket() Failed!\n");
        return -1;
    }
    bzero(&addr_r,sizeof(struct sockaddr_in));
    addr_r.sin_family = AF_INET;
    addr_r.sin_addr.s_addr = inet_addr(ip);
    addr_r.sin_port = htons(port); 

    if ((sock_s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        printf("CreateSocket: socket() Failed!\n");
        return -1;
    }
    bzero(&addr_s,sizeof(struct sockaddr_in));
    addr_s.sin_family = AF_INET;
    addr_s.sin_addr.s_addr = inet_addr(ip);
    addr_s.sin_port = htons(8888); 

    int enable = 1;
    if(setsockopt(sock_r, SOL_SOCKET, SO_REUSEADDR,  &enable, sizeof(int)) == -1){
        printf("CreateSocket: setsockopt() Failed!\n");
        return -1;
    }

    if(setsockopt(sock_s, SOL_SOCKET, SO_REUSEADDR,  &enable, sizeof(int)) == -1){
        printf("CreateSocket: setsockopt() Failed!\n");
        return -1;
    }

    if(bind(sock_r, (struct sockaddr *)&addr_r, sizeof(struct sockaddr)) == -1){
        printf("CreateSocket: bind() Failed!\n");
        return -1;
    }

    return 0;
}


int RecvMsg(unsigned char** msg, size_t* mlen){
    memset((void* )*msg, 0, *mlen);
    int addlen = sizeof(addr_r);
    if ((*mlen = recvfrom(sock_r, (void* )*msg, *mlen, 0, (struct sockaddr *)&addr_r, (socklen_t* )&addlen)) <= 0){
        printf("RecvMsg: recvfrom Failed!\n");
        return -1;
    }
    printf("recv: %d\n", *mlen);
    for (int i = 0; i<*mlen; i++) {
        printf("0x%02x ", *((*msg)+i));
    }
    printf("\n");
    return 0;
}

int SendMsg(void* msg, size_t mlen){
    if ((sendto(sock_s, msg, mlen, 0, (struct sockaddr *)&addr_s, sizeof(addr_s))) < 0){
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

void* RecvTest(){
	
unsigned char *msg = (unsigned char* )calloc(1024, sizeof(unsigned char));
size_t mlen = 1024;
    while (true) {

	if (RecvMsg(&msg, &mlen) != 0)
	{
	    printf("recvmsg Failed!\n");
	}

	usleep(1);
    }
}
int main(){
     
   	pthread_t send, recv;
     if(CreateSocket(IP_HOST, PORT) != 0){
		printf("CreatSocket Failed!\n");
		return 0;
	}
    pthread_create(&send, NULL, SendTest, NULL); 
    pthread_create(&recv, NULL, RecvTest, NULL); 
    pthread_join(send, NULL);
    pthread_join(recv, NULL);

}
