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
#include<sys/stat.h>
#include<sys/socket.h>
#include<sys/wait.h>
#include<sys/time.h>
#include<netinet/in.h>
#include<unistd.h>
#include<thread>
#include<mutex>
#include<condition_variable>

#include "Message.h"
#include "CertMng.h"
#include "CRLMng.h"
#include "CertOp.h"

#define SERVER_PORT 6666
#define SERVER_LISTEN_NUMBER 10
#define SERVER_DEFAULT_RECV_SIZE 1024

class Server{

public:
    Server();
    ~Server();

    static int Init();

    static void Start();
    static void Handler(int sock, struct sockaddr_in addr);
    static int deal_with_C0(unsigned char* data, size_t dlen, int sock);
    static int deal_with_C1(unsigned char* data, size_t dlen, int sock);
    static int deal_with_C2(unsigned char* data, size_t dlen, int sock);
    static int deal_with_C3(unsigned char* data, size_t dlen, int sock);
    static int deal_with_C4(unsigned char* data, size_t dlen, int sock);
    static int deal_with_C5(unsigned char* data, size_t dlen, int sock);
    static int deal_with_C6(unsigned char* data, size_t dlen, int sock);

    static void Wait();
    static void Notify();

private:
    static int init_ca(std::string key_filename, std::string crt_filename, s_CaInfo* ca);
    static int create_socket();
    static int check_ca();
    static int create_ca();
    static int create_ca_to_file(int ctype, int  stype, unsigned char* sign_crt_hashid8, EC_KEY* sign_key,
                              std::string key_filename, std::string crt_filename, s_CaInfo* ca);

    static int sock_fd_;
    static struct sockaddr_in addr_;

    static int server_count_;
    static std::mutex server_mutex_;
    static std::condition_variable server_condition_;

};

#endif
/**
* @}
**/

