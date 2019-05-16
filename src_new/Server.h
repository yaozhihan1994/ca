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

namespace SERVER{

#define SERVER_PORT 6666
#define SERVER_LISTEN_NUMBER 10
#define SERVER_DEFAULT_RECV_SIZE 1024

class Server{

public:
    Server();
    ~Server();

    static int Init();
    static int CreateSocket(const char* ip, uint16_t port);
    static int Start();

    static void deal_with_C0(unsigned char data[], size_t dlen, int sock);
    static void deal_with_C1(unsigned char data[], size_t dlen, int sock);
    static void deal_with_C2(unsigned char data[], size_t dlen, int sock);
    static void deal_with_C3(unsigned char data[], size_t dlen, int sock);
    static void deal_with_C4(unsigned char data[], size_t dlen, int sock);
    static void deal_with_C5(unsigned char data[], size_t dlen, int sock);


private:
    static int init_ca(string key_filename, EC_KEY** key, string crt_filename, Certificate_t** crt, 
                    unsigned char** crt_buffer, unsigned long** crt_buffer_len, unsigned char** crt_hashid8);
    static int check_ca();
    static int create_ca();
    static int create_ca_();
    int sock_fd_;
    struct sockaddr_in addr_;

};
}
#endif
/**
* @}
**/

