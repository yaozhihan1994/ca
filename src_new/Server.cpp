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
#include "Server.h"

using namespace SERVER;

Server::Server(){
}

Server::~Server(){
}

int Server::Init(){
    if (check_ca() == COMMON_SUCCESS) {
        printf("Init check_ca succ\n");
        printf("Init init_ca start\n");
        if (init_ca(ROOTCAKEY, &g_rootca_key, ROOTCACRT, &g_rootca_crt, 
                    &g_rootca_buffer, &g_rootca_buffer_size, &g_rootca_hashid8) != COMMON_SUCCESS) {
            printf("Init init_rootca fail\n");
            return COMMON_ERROR;
        }
        if (init_ca(SUBROOTCAKEY, &g_subrootca_key, SUBROOTCACRT, &g_subrootca_crt, 
                    &g_subrootca_buffer, &g_subrootca_buffer_size, &g_subrootca_hashid8) != COMMON_SUCCESS) {
            printf("Init init_subrootca fail\n");
            return COMMON_ERROR;
        }
        if (init_ca(ECAKEY, &g_eca_key, ECACRT, &g_eca_crt, 
                    &g_eca_buffer, &g_eca_buffer_size, &g_eca_hashid8) != COMMON_SUCCESS) {
            printf("Init init_eca fail\n");
            return COMMON_ERROR;
        }
        if (init_ca(PCAKEY, &g_pca_key, PCACRT, &g_pca_crt, 
                    &g_pca_buffer, &g_pca_buffer_size, &g_pca_hashid8) != COMMON_SUCCESS) {
            printf("Init init_pca fail\n");
            return COMMON_ERROR;
        }
        if (init_ca(RCAKEY, &g_rca_key, RCACRT, &g_rca_crt, 
                    &g_rca_buffer, &g_rca_buffer_size, &g_rca_hashid8) != COMMON_SUCCESS) {
            printf("Init init_rca fail\n");
            return COMMON_ERROR;
        }
        if (init_ca(CCAKEY, &g_cca_key, CCACRT, &g_cca_crt, 
                    &g_cca_buffer, &g_cca_buffer_size, &g_cca_hashid8) != COMMON_SUCCESS) {
            printf("Init init_cca fail\n");
            return COMMON_ERROR;
        }
        printf("Init init_ca succ\n");
        return COMMON_SUCCESS;
    }else{
        printf("Init check_ca fail\n");
        printf("Init create_ca start\n");
        if(create_ca() != COMMON_SUCCESS){
            printf("Init create_ca fail\n");
            return COMMON_ERROR;
        }
        printf("Init create_ca succ\n");
        return COMMON_SUCCESS;
    }
}

int Server::check_ca(){
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
    return COMMON_SUCCESS;
}

int Server::init_ca(string key_filename, EC_KEY** key, string crt_filename, Certificate_t** crt, 
                    unsigned char** crt_buffer, unsigned long** crt_buffer_len, unsigned char** crt_hashid8){

    *key = Common::FileToKey(key_filename.c_str());
    if (*key == NULL) {
        printf("init_ca FileToKey: %s fail\n", key_filename.c_str());
        return COMMON_ERROR;
    }
    *crt = CertificateManage::FileToCertificate(crt_filename.c_str());
    if (crt == NULL) {
        printf("init_ca FileToCertificate: %s fail\n", crt_filename.c_str());
        return COMMON_ERROR;
    }
    if (CertificateManage::CertificateToBuffer(crt_buffer, crt_buffer_len, *crt) != COMMON_SUCCESS) {
        printf("init_ca CertificateToBuffer: %s fail\n", crt_filename.c_str());
        return COMMON_ERROR;
    }
    unsigned char* hash = NULL;
    size_t hlen = 0;
    if (Common::Sm3Hash(*crt_buffer, *crt_buffer_len, &hash, &hlen) != COMMON_SUCCESS) {
        printf("init_ca Sm3Hash: %s fail\n", crt_filename.c_str());
        return COMMON_ERROR;
    }
    unsigned char* hashid8 = (unsigned char* )malloc(8);
    if (!hashid8) {
        printf("init_ca malloc hashid8: %s fail\n", crt_filename.c_str());
        return COMMON_ERROR;
    }
    memcpy(hashid8, hash+32-8, 8);
    free(hash);
    *crt_hashid8 = hashid8;
    return COMMON_SUCCESS;
}

int Server::create_ca(){
    int ret = COMMON_ERROR;
    //


    err:{

    }
    return ret;
}

int Server::create_ca_(){
    int ret = COMMON_ERROR;
    //


    err:{

    }
    return ret;
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

int Server::Start(){

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
                t = std::thread(Server::SendErrorCode, cmd);
                break;
            }
        }
        t.join();
    //  t.detach();
        if (data) {
            free(data);
        }
        usleep(1);
    }

}

void Server::deal_with_C0(unsigned char data[], size_t dlen, int sock){
    unsigned char cmd = 0x00;
    int type = (int)(*data);
    int flag = 0;
    unsigned  char* msg = NULL;
    size_t meln = 0;
    switch (type) {
        case 1:{
            //send eca crt
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
            break;
        }
    }
    if (msg) {
        free(msg);
    }
    if (flag == 0) {
        Message::SendErrorCode(sock, cmd);
    }
}

void Server::deal_with_C1(unsigned char data[], size_t dlen, int sock){
    int ret = COMMON_ERROR;
    unsigned char cmd = 0x01;
    int flag = 0;
    EC_KEY* key = NULL;
    unsigned char* pub_key = NULL;
    unsigned char* pri_key = NULL;
    Certificate_t *ecrt = NULL;
    unsigned char* ecrt_buffer = NULL;
    size_t ecrt_buffer_size = 0;
    unsigned char* msg = NULL;
    size_t mlen = 0;
    unsigned char* buffer = NULL;
    size_t blen = 0;

    if (Common::VerifyDeviceId(data, dlen) != COMMON_SUCCESS) {
        printf("deal_with_C1: VerifyDeviceId fail\n");
        goto err;
    }
    key = Common::CreateSm2KeyPair();
    if (!key) {
        printf("deal_with_C1: CreateSm2KeyPair fail\n");
        goto err;
    }
    pub_key = Common::get_sm2_public_key(key);
    if (!pub_key) {
        printf("deal_with_C1: get_sm2_public_key fail\n");
        goto err;
    }
    pri_key = Common::get_sm2_private_key(key);
    if (!pri_key) {
        printf("deal_with_C1: get_sm2_private_key fail\n");
        goto err;
    }
    ecrt = CertificateManage::CreateCertificate(e_CertificateType.E_CA, 
                                                               e_SubjectType.SubjectType_enrollmentCredential, pub_key, g_eca_hash, g_eca_key);
    if (!ecrt) {
        printf("deal_with_C1: CreateCertificate ecrt fail\n");
        goto err;
    }
    if (CertificateManage::CertificateToBuffer(&ecrt_buffer, &ecrt_buffer_size, ecrt) != COMMON_SUCCESS) {
        printf("deal_with_C1: CertificateToBuffer ecrt fail\n");
        goto err;
    }
    blen = PRIVATE_KEY_LENGTH+ecrt_buffer_size;
    buffer = (unsigned char* )malloc(blen);
    if (!buffer) {
        printf("deal_with_C1: malloc buffer buffer fail\n");
        goto err;
    }
    memcpy(buffer, pri_key, PRIVATE_KEY_LENGTH);
    memcpy(buffer+PRIVATE_KEY_LENGTH, ecrt_buffer, ecrt_buffer_size);

    if (Message::MessageEncode(cmd, buffer, blen, &msg, &mlen) != COMMON_SUCCESS) {
        printf("deal_with_C1: MessageEncode ecrt fail\n");
        goto err;
    }
    if (Message::SendMsg(sock, msg, mlen) != COMMON_SUCCESS) {
        printf("deal_with_C1: SendMsg ecrt fail\n");
        goto err;
    }

    ret = COMMON_SUCCESS;
    err:{
        if (buffer) {
            free(buffer);
        }
        if (msg) {
            free(msg);
        }
        if (pub_key) {
            free(pub_key);
        }
        if (key) {
            EC_KEY_free(key);
        }
        if (ecrt) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Certificate, ecrt);
        }
        if (ret != COMMON_SUCCESS) {
            Message::SendErrorCode(sock, cmd);
        }
    }
}


void Server::deal_with_C2(unsigned char data[], size_t dlen, int sock){
    int ret = COMMON_ERROR;
    unsigned char cmd = 0x02;
    int flag = 0;
    unsigned char* crt_buffer = NULL;
    size_t crt_buffer_size = 0;
    unsigned char* key_buffer = NULL;
    size_t key_buffer_size = 0;
    unsigned char* msg = NULL;
    size_t mlen = 0;
    unsigned char* buffer = NULL;
    size_t blen = 0;

    Certificate_t* ecrt = NULL;
    if((ecrt = CertificateManage::BufferToCertificate(data, dlen)) == NULL){
        printf("deal_with_C2: BufferToCertificate fail\n");
        goto err;
    }
    if (CertificateManage::CertificateVerify(g_eca_key, ecrt) != COMMON_SUCCESS) {
        printf("deal_with_C2: CertificateVerify fail\n");
        goto err;
    }

    if(CertificateManage::get_pcrt_and_pkey(&crt_buffer, &crt_buffer_size, &key_buffer, &key_buffer_size) != COMMON_SUCCESS){
        printf("deal_with_C2: get_pcrt_and_pkey fail\n");
        goto err;
    }

    blen = crt_buffer_size+PRIVATE_KEY_LENGTH;
    buffer = (unsigned char* )malloc(blen);
    if (!buffer) {
        printf("deal_with_C2: malloc buffer buffer fail\n");
        goto err;
    }
    memcpy(buffer, key_buffer, PRIVATE_KEY_LENGTH);
    memcpy(buffer+PRIVATE_KEY_LENGTH, crt_buffer, crt_buffer_size);

    if (Message::MessageEncode(cmd, buffer, blen, &msg, &mlen) != COMMON_SUCCESS) {
        printf("deal_with_C2: MessageEncode pcrt fail\n");
        goto err;
    }
    if (Message::SendMsg(sock, msg, mlen) != COMMON_SUCCESS) {
        printf("deal_with_C2: SendMsg pcrt fail\n");
        goto err;
    }

    ret = COMMON_SUCCESS;
    err:{
        if (crt_buffer) {
            free(crt_buffer);
        }
        if (key_buffer) {
            free(key_buffer);
        }
        if (msg) {
            free(msg);
        }
        if (buffer) {
            free(buffer);
        }
        if (ecrt) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Certificate, ecrt);
        }
        if (ret != COMMON_SUCCESS) {
            Message::SendErrorCode(sock, cmd);
        }
    }
}


void Server::deal_with_C3(unsigned char data[], size_t dlen, int sock){
    int ret = COMMON_ERROR;
    unsigned char cmd = 0x03;
    int flag = 0;
    unsigned char* crt_buffer = NULL;
    size_t crt_buffer_size = 0;
    unsigned char* key_buffer = NULL;
    size_t key_buffer_size = 0;
    unsigned char* msg = NULL;
    size_t mlen = 0;
    unsigned char* buffer = NULL;
    size_t blen = 0;

    Certificate_t* ecrt = NULL;
    if((ecrt = CertificateManage::BufferToCertificate(data, dlen)) == NULL){
        printf("deal_with_C3: BufferToCertificate fail\n");
        goto err;
    }
    if (CertificateManage::CertificateVerify(g_eca_key, ecrt) != COMMON_SUCCESS) {
        printf("deal_with_C3: CertificateVerify fail\n");
        goto err;
    }

    if(CertificateManage::get_rcrt_and_rkey(&crt_buffer, &crt_buffer_size, &key_buffer, &key_buffer_size)){
        printf("deal_with_C3: get_rcrt_and_rkey fail\n");
        goto err;
    }

    blen = crt_buffer_size+PRIVATE_KEY_LENGTH;
    buffer = (unsigned char* )malloc(blen);
    if (!buffer) {
        printf("deal_with_C3: malloc buffer buffer fail\n");
        goto err;
    }
    memcpy(buffer, key_buffer, PRIVATE_KEY_LENGTH);
    memcpy(buffer+PRIVATE_KEY_LENGTH, crt_buffer, crt_buffer_size);

    if (Message::MessageEncode(cmd, buffer, blen, &msg, &mlen) != COMMON_SUCCESS) {
        printf("deal_with_C3: MessageEncode pcrt fail\n");
        goto err;
    }
    if (Message::SendMsg(sock, msg, mlen) != COMMON_SUCCESS) {
        printf("deal_with_C3: SendMsg pcrt fail\n");
        goto err;
    }

    ret = COMMON_SUCCESS;
    err:{
        if (crt_buffer) {
            free(crt_buffer);
        }
        if (key_buffer) {
            free(key_buffer);
        }
        if (msg) {
            free(msg);
        }
        if (buffer) {
            free(buffer);
        }
        if (ecrt) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Certificate, ecrt);
        }
        if (ret != COMMON_SUCCESS) {
            Message::SendErrorCode(sock, cmd);
        }
    }
}


void Server::deal_with_C4(unsigned char data[], size_t dlen, int sock){
    int ret = COMMON_ERROR;
    unsigned char cmd = 0x04;
    size_t error_crt_size = (int)(data[0]);
    unsigned char error_crt_buffer[error_crt_size];
    memcpy(error_crt_buffer, data+1, error_crt_size);
    size_t ecrt_size = dlen - error_crt_size -1;
    unsigned char ecrt_buffer[ecrt_size];
    memcpy(ecrt_buffer, data+1+error_crt_size, ecrt_size);
    Certificate_t* error_crt = NULL;
    Certificate_t* ecrt = NULL;
    unsigned char* error_crt_hash = NULL;
    size_t error_crt_hash_size = 0;
    size_t error_crt_end_gmtime = 0;
    size_t error_crt_start_difftime = 0;
    Crl_t* crl = NULL;
    string name;
    if((ecrt = CertificateManage::BufferToCertificate(ecrt_buffer, ecrt_size)) == NULL){
        printf("deal_with_C4: BufferToCertificate fail\n");
        goto err;
    }
    if (CertificateManage::CertificateVerify(g_eca_key, ecrt) != COMMON_SUCCESS) {
        printf("deal_with_C4: CertificateVerify fail\n");
        goto err;
    }

    if(Common::Sm3Hash(ecrt_buffer, ecrt_size, &error_crt_hash, &error_crt_hash_size) != COMMON_SUCCESS){
        printf("deal_with_C4: Sm3Hash fail\n");
        goto err;
    }

    if((error_crt = CertificateManage::BufferToCertificate(error_crt_buffer, error_crt_size)) == NULL){
        printf("deal_with_C4: BufferToCertificate fail\n");
        goto err;
    }
    //maybe need some way to check this crt , then decide whether need to revoke it
    error_crt_end_gmtime = Common::get_time_by_diff(error_crt->validityRestrictions.choice.timeStartAndEnd.endValidity);
    error_crt_start_difftime = error_crt->validityRestrictions.choice.timeStartAndEnd.startValidity;

    if ((crl = CrlManage::CreateCRL(g_cca_key, g_subrootca_hashid8, g_cca_hashid8, error_crt_hash+32-10, error_crt_start_difftime)) == NULL) {
        printf("deal_with_C4: CreateCRL fail\n");
        goto err;
    }

    name = Common::ToString(error_crt_end_gmtime); 
    name = name + "_" + Common::ToString(crl->unsignedCrl.crlSerial);
    CrlManage::set_crl_list(name);
    name =  CRL_FILENAME+name;

    if (CrlManage::CrlToFile(name.c_str(), crl) != COMMON_SUCCESS) {
        printf("deal_with_C4: CrlToFile fail\n");
        goto err;
    }

    ret = COMMON_SUCCESS;
    err:{
        if (error_crt_hash) {
            free(error_crt_hash);
        }
        if (ret != COMMON_SUCCESS) {
            Message::SendErrorCode(sock, cmd);
        }
    }
}

void Server::deal_with_C5(unsigned char data[], size_t dlen, int sock){
    int ret = COMMON_ERROR;
    unsigned char cmd = 0x03;
    int flag = 0;
    Certificate_t* ecrt = NULL;

    if((ecrt = CertificateManage::BufferToCertificate(data, dlen)) == NULL){
        printf("deal_with_C5: BufferToCertificate fail\n");
        goto err;
    }
    if (CertificateManage::CertificateVerify(g_eca_key, ecrt) != COMMON_SUCCESS) {
        printf("deal_with_C5: CertificateVerify fail\n");
        goto err;
    }

    if(CrlManage::send_crls(sock cmd) != COMMON_SUCCESS){
        printf("deal_with_C5: send_crls fail\n");
        goto err;
    }

    ret = COMMON_SUCCESS;
    err:{
        if (ecrt) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Certificate, ecrt);
        }
        if (ret != COMMON_SUCCESS) {
            Message::SendErrorCode(sock, cmd);
        }
    }
}

int main(int argc, char* argv[]) {

    if(Server::Init() != COMMON_SUCCESS){
        printf("main: Init fail\n");
        return 0;
    }

    Server::Start();

    return 0;
}
/**
* @}
**/
