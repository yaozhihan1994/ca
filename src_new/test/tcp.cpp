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

struct sockaddr_in addr_;
int sock;
int create_socket(){

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("CreateSocket: socket() Failed!\n");
        return -1;
    } 

    bzero(&addr_,sizeof(struct sockaddr_in));
    addr_.sin_family = AF_INET;
    addr_.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr_.sin_port = htons(6666); 
/*
    int enable = 1;
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,  &enable, sizeof(int)) == -1){
        printf("CreateSocket: setsockopt() Failed!\n");
        return -1;
    }

    if(bind(sock, (struct sockaddr *)&addr_, sizeof(struct sockaddr)) == -1){
        printf("CreateSocket: bind() Failed!\n");
        return -1;
    }

    if(listen(sock, 10) == -1){
         printf("CreateSocket: listen socket error\n");
         return 0;
    }
*/
    return 0;
}


void Recv(){
	struct sockaddr_in conn_addr_;
	int sin_size = sizeof(struct sockaddr_in);
	int conn = 0;
	if((conn = accept(sock, (struct sockaddr*)&conn_addr_, (socklen_t*)&sin_size)) == -1){
	     printf("Handler: accept socket error\n");
	     return;
	}
        unsigned char buffer[1024] = {};
        int len = 0;
        if((len = recv(conn, (void*)buffer, 1024, 0)) <= 0){
             printf("Handler: recv msg fail\n");
             return; 
        }
	printf("recv :\n");
	for(int i = 0; i<len; i++){
		printf("0x%02x ",buffer[i]);
	}
	printf("\n");
}

int main(){
	if (create_socket() != 0) {
		printf("Start: create_socket fail\n");
		return 0;
	}

 	if (connect(sock, (struct sockaddr *)&addr_,sizeof(struct sockaddr_in)) == -1){
		perror("connect error"); 
		exit(1);
     	} 

	unsigned char test[10] = {0xff, 0xff, 0x00, 0x00, 0x00, 0x02, 0x05, 0x05, 0x02, 0xff};
	size_t len = 10;

	if(send(sock, test, len, 0) == -1){
		perror("send fail");
	}
	printf("send :%d\n",len);
	for(int i = 0; i<len; i++){
		printf("0x%02x ",*(test+i));
	}
	printf("\n");

	getchar();
return 0;
}
