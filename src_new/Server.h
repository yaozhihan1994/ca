/***********************************************
* @addtogroup Nebula
* @{
* @file  : Server.h
* @brief :
* @date  : 2019-05-13
***********************************************/

//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------

#ifndef SERVER_H_
#define SERVER_H_

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<unistd.h>
#include<thread>
#include<mutex>

#include "Common.h"
#include "Message.h"
#include "CertificateManage.h"
#include "CrlManage.h"

namespace SERVER{

#define SERVER_PORT 6666
#define SERVER_LISTEN_NUMBER 10
#define SERVER_DEFAULT_RECV_SIZE 1024

extern EC_KEY* g_rootca_key;
extern EC_KEY* g_subrootca_key;
extern EC_KEY* g_eca_key;
extern EC_KEY* g_pca_key;
extern EC_KEY* g_rca_key;
extern EC_KEY* g_cca_key;

extern Certificate_t* g_rootca_crt;
extern Certificate_t* g_subrootca_crt;
extern Certificate_t* g_eca_crt;
extern Certificate_t* g_pca_crt;
extern Certificate_t* g_rca_crt;
extern Certificate_t* g_cca_crt;

extern unsigned char* g_rootca_buffer;
extern unsigned char* g_subrootca_buffer;
extern unsigned char* g_eca_buffer;
extern unsigned char* g_pca_buffer;
extern unsigned char* g_rca_buffer;
extern unsigned char* g_cca_buffer;

extern unsigned char* g_rootca_hash;
extern unsigned char* g_subrootca_hash;
extern unsigned char* g_eca_hash;
extern unsigned char* g_pca_hash;
extern unsigned char* g_rca_hash;
extern unsigned char* g_cca_hash;

class Server{

public:
    Server();
    ~Server();

    static int Init();
    static int CreateCA();
    static int CreateSocket(const char* ip, uint16_t port);
    static int Handler();

    static int deal_with_C0(unsigned char data[], size_t dlen, int sock);
    static int deal_with_C1(unsigned char data[], size_t dlen, int sock);
    static int deal_with_C2(unsigned char data[], size_t dlen, int sock);
    static int deal_with_C3(unsigned char data[], size_t dlen, int sock);
    static int deal_with_C4(unsigned char data[], size_t dlen, int sock);
    static int deal_with_C5(unsigned char data[], size_t dlen, int sock);


private:

    int sock_fd_;
    struct sockaddr_in addr_;

};
}
#endif
/**
* @}
**/

