/***********************************************
* @addtogroup Nebula
* @{
* @file  : Server.cpp
* @brief :
* @date  : 2019-05-13
***********************************************/
 
//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------

#include "Server.h"

using namespace SERVER;
using namespace MESSAGE;

EC_KEY* g_rootca_key = NULL;
EC_KEY* g_subrootca_key = NULL;
EC_KEY* g_eca_key = NULL;
EC_KEY* g_pca_key = NULL;
EC_KEY* g_rca_key = NULL;
EC_KEY* g_cca_key = NULL;

Certificate_t* g_rootca_crt = NULL;
Certificate_t* g_subrootca_crt = NULL;
Certificate_t* g_eca_crt = NULL;
Certificate_t* g_pca_crt = NULL;
Certificate_t* g_rca_crt = NULL;
Certificate_t* g_cca_crt = NULL;

unsigned char* g_rootca_buffer = NULL;
unsigned char* g_subrootca_buffer = NULL;
unsigned char* g_eca_buffer = NULL;
unsigned char* g_pca_buffer = NULL;
unsigned char* g_rca_buffer = NULL;
unsigned char* g_cca_buffer = NULL;

unsigned int g_rootca_buffer_size = 0;
unsigned int g_subrootca_buffer_size = 0;
unsigned int g_eca_buffer_size = 0;
unsigned int g_pca_buffer_size = 0;
unsigned int g_rca_buffer_size = 0;
unsigned int g_cca_buffer_size = 0;

unsigned char* g_rootca_hash = NULL;
unsigned char* g_subrootca_hash = NULL;
unsigned char* g_eca_hash = NULL;
unsigned char* g_pca_hash = NULL;
unsigned char* g_rca_hash = NULL;
unsigned char* g_cca_hash = NULL;


Server::Server(){
}

Server::~Server(){
    close(conn_fd_);
    close(sock_fd_);
}

int Server::Init(){
    //check ca crt and key file
    string filename[12];
    filename[0] = ROOTCACRT;
    filename[1] = ROOTCAKEY;
    filename[2] = SUBROOTCACRT;
    filename[3] = SUBROOTCAKEY;
    filename[4] = ECACRT;
    filename[5] = ECAKEY;
    filename[6] = PCACRT;
    filename[7] = PCAKEY;
    filename[8] = RCACRT;
    filename[9] = RCAKEY;
    filename[10] = CCACRT;
    filename[11] = CCAKEY;
    for (int i=0; i<12; i++) {
        if (access(filename[i].c_str(), F_OK) == -1) {
            printf("Check CA file: %s not exists\n", filename[i].c_str());
            return COMMON_ERROR;
        }
    }

    //pcrt loading to list
    CertificateManage::init_pcrt_list();

    //rcrt loading to list
    CertificateManage::init_rcrt_list();

    //crl loading to list
    CrlManage::init_crl_list();
}


int Server::CreateSocket(const char* ip, uint16_t port){

    if ((sock_fd_ = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("CreateSocket: socket() Failed!\n");
        return COMMON_ERROR;
    } 

    bzero(&addr_,sizeof(struct sockaddr_in));
    addr_.sin_family = AF_INET;
    addr_.sin_addr.s_addr = INADDR_ANY;
    addr_.sin_port = htons(port); 

    int enable = 1;
    if(setsockopt(sock_fd_, SOL_SOCKET, SO_REUSEADDR,  &enable, sizeof(int)) == -1){
        printf("CreateSocket: setsockopt() Failed!\n");
        return COMMON_ERROR;
    }

    if(bind(sock_fd_, (struct sockaddr *)&addr_, sizeof(struct sockaddr)) == -1){
        printf("CreateSocket: bind() Failed!\n");
        return COMMON_ERROR;
    }

    if(listen(sock_fd_, SERVER_LISTEN_NUMBER) == -1){
         printf("CreateSocket: listen socket error\n");
         return 0;
    }
    return COMMON_SUCCESS;
}

int Server::Handler(){

    while (true) {
        struct sockaddr_in conn_addr_;
        int sin_size = sizeof(struct sockaddr_in);
        int conn = 0;
        if((conn = accept(sock_fd_, (struct sockaddr*)&conn_addr_, &sin_size)) == -1){
             printf("Handler: accept socket error\n");
             return COMMON_ERROR; 
        }
        unsigned char buffer[SERVER_DEFAULT_RECV_SIZE] = {};
        int len = 0;
        if((len_ = recv(conn, (void*)buffer, SERVER_DEFAULT_RECV_SIZE, 0)) <= 0){
             printf("Handler: recv msg fail\n");
             return COMMON_ERROR; 
        }

        unsigned char cmd = 0xff;
        unsigned char* data = NULL;
        size_t dlen = 0;
        if(Message::MessageDecode(buffer, len, &cmd, &data, &dlen) != COMMON_SUCCESS){
             printf("Handler: MessageDecode fail\n");
             return COMMON_ERROR; 
        }

        unsigned char data_[dlen];
        memcpy(data_, data, dlen);
        std::thread t;
        switch (cmd) {
            case 0x00:{
                t = std::thread(Server::deal_with_C0, data_, dlen, conn);
                break;
            }
            case 0x01:{
                t = std::thread(Server::deal_with_C1, data_, dlen, conn);
                break;
            }
            case 0x02:{
                t = std::thread(Server::deal_with_C2, data_, dlen, conn);
                break;
            }
            case 0x03:{
                t = std::thread(Server::deal_with_C3, data_, dlen, conn);
                break;
            }
            case 0x04:{
                t = std::thread(Server::deal_with_C4, data_, dlen, conn);
                break;
            }
            case 0x05:{
                t = std::thread(Server::deal_with_C5, data_, dlen, conn);
                break;
            }
            default:{
                printf("Handler: unknow cmd type\n");
                t = std::thread(Server::SendErrorCode);
                break;
            }
        }
        t.join();
    //  t.detach();
        if (data) {
            free(data);
        }
        if (conn_addr_) {
            close(conn_fd_);
        }
    }
    usleep(1);
}

int Server::deal_with_C0(unsigned char data[], size_t dlen, int sock){
    printf("MessageManageThread: cmd = 0 !\n");
    unsigned char cmd = 0x00;
    int type = (int)(*data);
    int flag = 0;
    switch (type) {
        case 1:{
            //send eca crt
            unsigned  char* msg = NULL;
            size_t meln = 0;
            if(Message::MessageEncode(cmd, g_eca_buffer, g_eca_buffer_size, &msg, &mlen) != COMMON_SUCCESS){
                printf("deal_with_C0: MessageEncode fail\n");
                break;
            }
            if((Message::SendMsg(sock, msg, mlen) != COMMON_SUCCESS){
                printf("deal_with_C0: SendMsg fail\n");
                free(msg);
                break;
            }
            flag = 1;
            break;
        }
        case 2:{
            //send pca crt
            unsigned  char* msg = NULL;
            size_t meln = 0;
            if(Message::MessageEncode(cmd, g_pca_buffer, g_pca_buffer_size, &msg, &mlen) != COMMON_SUCCESS){
                printf("deal_with_C0: MessageEncode fail\n");
                break;
            }
            if((Message::SendMsg(sock, msg, mlen) != COMMON_SUCCESS){
                printf("deal_with_C0: SendMsg fail\n");
                free(msg);
                break;
            }
            flag = 1;
            break;
        }
        case 3:{
            //send rca crt
            unsigned  char* msg = NULL;
            size_t meln = 0;
            if(Message::MessageEncode(cmd, g_rca_buffer, g_rca_buffer_size, &msg, &mlen) != COMMON_SUCCESS){
                printf("deal_with_C0: MessageEncode fail\n");
                break;
            }
            if((Message::SendMsg(sock, msg, mlen) != COMMON_SUCCESS){
                printf("deal_with_C0: SendMsg fail\n");
                free(msg);
                break;
            }
            flag = 1;
            break;
        }
        default:{
            printf("Handler: unknow request ca crt type\n");
            Message::SendErrorCode(sock, cmd);
            break;
        }
    }


    if (flag == 0) {
        Message::SendErrorCode(sock, cmd);
    }
}

int main(int argc, char* argv[]) {

    std::mutex mut;
    std::lock_guard<std::mutex> guard(mut);


    return 0;
}
/**
* @}
**/
