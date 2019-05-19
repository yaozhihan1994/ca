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

extern s_CaInfo g_rootca;
extern s_CaInfo g_subrootca;
extern s_CaInfo g_eca;
extern s_CaInfo g_pca;
extern s_CaInfo g_rca;
extern s_CaInfo g_cca;

int Server::sock_fd_ = -1;
struct sockaddr_in Server::addr_;
int Server::server_count_ = 10;
std::mutex Server::server_mutex_;
std::condition_variable Server::server_condition_;

Server::Server(){
}

Server::~Server(){
}

int Server::Init(){
    if (check_ca() == COMMON_SUCCESS) {
        printf("Init check_ca succ\n");
        printf("Init init_ca start\n");
        if (init_ca(ROOTCAKEY, ROOTCACRT, &g_rootca) != COMMON_SUCCESS) {
            printf("Init init_rootca fail\n");
            return COMMON_ERROR;
        }
        if (init_ca(SUBROOTCAKEY, SUBROOTCACRT, &g_subrootca) != COMMON_SUCCESS) {
            printf("Init init_subrootca fail\n");
            return COMMON_ERROR;
        }
        if (init_ca(ECAKEY, ECACRT, &g_eca) != COMMON_SUCCESS) {
            printf("Init init_eca fail\n");
            return COMMON_ERROR;
        }
        if (init_ca(PCAKEY, PCACRT, &g_pca) != COMMON_SUCCESS) {
            printf("Init init_pca fail\n");
            return COMMON_ERROR;
        }
        if (init_ca(RCAKEY, RCACRT, &g_rca) != COMMON_SUCCESS) {
            printf("Init init_rca fail\n");
            return COMMON_ERROR;
        }
        if (init_ca(CCAKEY, CCACRT, &g_cca) != COMMON_SUCCESS) {
            printf("Init init_cca fail\n");
            return COMMON_ERROR;
        }
        printf("Init init_ca succ\n");
    }else{
        printf("Init check_ca fail\n");
        printf("Init create_ca start\n");
        if(create_ca() != COMMON_SUCCESS){
            printf("Init create_ca fail\n");
            return COMMON_ERROR;
        }
        printf("Init create_ca succ\n");
    }
    return COMMON_SUCCESS;
}

int Server::check_ca(){
    //check ca crt and key file
    std::string filename[12];
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

int Server::init_ca(std::string key_filename, std::string crt_filename, s_CaInfo* ca){

    ca->key = Common::FileToKey(key_filename.c_str());
    if (ca->key == NULL) {
        printf("init_ca FileToKey: %s fail\n", key_filename.c_str());
        return COMMON_ERROR;
    }
    ca->crt = CertificateManage::FileToCertificate(crt_filename.c_str());
    if (ca->crt == NULL) {
        printf("init_ca FileToCertificate: %s fail\n", crt_filename.c_str());
        return COMMON_ERROR;
    }
    if (CertificateManage::CertificateToBuffer(&(ca->buffer), &(ca->blen), ca->crt) != COMMON_SUCCESS) {
        printf("init_ca CertificateToBuffer: %s fail\n", crt_filename.c_str());
        return COMMON_ERROR;
    }
    unsigned char* hash = NULL;
    size_t hlen = 0;
    if (Common::Sm3Hash(ca->buffer, ca->blen, &hash, &hlen) != COMMON_SUCCESS) {
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
    ca->hashid8 = hashid8;
    return COMMON_SUCCESS;
}

int Server::create_ca(){
    //create root ca
    if (create_ca_to_file(ROOT_CA_CRT, SubjectType_rootCa, NULL, NULL, ROOTCAKEY, ROOTCACRT, &g_rootca) != COMMON_SUCCESS) {
        printf("create_ca create_ca_to_file root ca fail\n");
        return COMMON_ERROR;
    }
    //create subroot ca
    if (create_ca_to_file(SUBROOT_CA_CRT, SubjectType_rootCa, 
                          g_rootca.hashid8, g_rootca.key, SUBROOTCAKEY, SUBROOTCACRT, &g_subrootca) != COMMON_SUCCESS) {
        printf("create_ca create_ca_to_file subroot ca fail\n");
        return COMMON_ERROR;
    }
    //create e ca
    if (create_ca_to_file(E_CA_CRT, SubjectType_enrollmentAuthority, 
                          g_subrootca.hashid8, g_subrootca.key, ECAKEY, ECACRT, &g_eca) != COMMON_SUCCESS) {
        printf("create_ca create_ca_to_file e ca fail\n");
        return COMMON_ERROR;
    }
    //create p ca
    if (create_ca_to_file(P_CA_CRT, SubjectType_authorizationAuthority, 
                          g_subrootca.hashid8, g_subrootca.key, PCAKEY, PCACRT, &g_pca) != COMMON_SUCCESS) {
        printf("create_ca create_ca_to_file p ca fail\n");
        return COMMON_ERROR;
    }
    //create r ca
    if (create_ca_to_file(R_CA_CRT, SubjectType_authorizationAuthority, 
                          g_subrootca.hashid8, g_subrootca.key, RCAKEY, RCACRT, &g_rca) != COMMON_SUCCESS) {
        printf("create_ca create_ca_to_file r ca fail\n");
        return COMMON_ERROR;
    }
    //create c ca
    if (create_ca_to_file(C_CA_CRT, SubjectType_crlSigner, 
                          g_subrootca.hashid8, g_subrootca.key, CCAKEY, CCACRT, &g_cca) != COMMON_SUCCESS) {
        printf("create_ca create_ca_to_file c ca fail\n");
        return COMMON_ERROR;
    }
    return COMMON_SUCCESS;
}

int Server::create_ca_to_file(int ctype, int  stype, unsigned char* sign_crt_hashid8, EC_KEY* sign_key,
                              std::string key_filename, std::string crt_filename, s_CaInfo* ca){
    int ret = COMMON_ERROR;
    EC_KEY* key = NULL;
    Certificate_t* crt = NULL;
    unsigned char* pub_key = NULL;
    unsigned char* hash = NULL;
    size_t hlen = 0;
    unsigned char* hashid8 = NULL;

    key = Common::CreateSm2KeyPair();
    if (!key) {
        printf("create_ca_to_file CreateSm2KeyPair fail\n");
        goto err;
    }
    pub_key = Common::get_sm2_public_key(key);
    if (!pub_key) {
        printf("create_ca_to_file get_sm2_public_key fail\n");
        goto err;
    }
    if (ctype == ROOT_CA_CRT) {
        crt = CertificateManage::CreateCertificate(ctype, stype, pub_key, NULL, key);
    }else{
        crt = CertificateManage::CreateCertificate(ctype, stype, pub_key, sign_crt_hashid8, sign_key);
    }
    
    if (!crt) {
        printf("create_ca_to_file CreateCertificate crt fail\n");
        goto err;
    }

    if(CertificateManage::CertificateToFile(crt_filename.c_str(), crt) !=COMMON_SUCCESS){
        printf("create_ca_to_file CertificateToFile fail\n");
        goto err;
    }

    if(Common::KeyToFile(key_filename.c_str(), key) != COMMON_SUCCESS){
        printf("create_ca_to_file KeyToFile fail\n");
        goto err;
    }

    if (CertificateManage::CertificateToBuffer(&(ca->buffer), &(ca->blen), crt) != COMMON_SUCCESS) {
        printf("create_ca_to_file CertificateToBuffer: %s fail\n", crt_filename.c_str());
        goto err;
    }

    if (Common::Sm3Hash(ca->buffer, ca->blen, &hash, &hlen) != COMMON_SUCCESS) {
        printf("create_ca_to_file Sm3Hash: %s fail\n", crt_filename.c_str());
        goto err;
    }

    hashid8 = (unsigned char* )malloc(8);
    if (!hashid8) {
        printf("create_ca_to_file malloc hashid8: %s fail\n", crt_filename.c_str());
        goto err;
    }
    memcpy(hashid8, hash+32-8, 8);

    ca->key = key;
    ca->crt = crt;
    ca->hashid8 = hashid8;

    ret = COMMON_SUCCESS;
    err:{
        if (pub_key) {
            free(pub_key);
        }
        if (hash) {
            free(hash);
        }
    }
    return ret;
}


int Server::create_socket(){

    if ((sock_fd_ = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("CreateSocket: socket() Failed!\n");
        return COMMON_ERROR;
    } 

    bzero(&addr_,sizeof(struct sockaddr_in));
    addr_.sin_family = AF_INET;
    addr_.sin_addr.s_addr = INADDR_ANY;
    addr_.sin_port = htons(SERVER_PORT); 

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

void Server::Start(){
    if (create_socket() != COMMON_SUCCESS) {
         printf("Start: create_socket fail\n");
         return;
    }
    printf("Start: create_socket succ\n");
    while (true) {
        struct sockaddr_in conn_addr_;
        int sin_size = sizeof(struct sockaddr_in);
        int conn = 0;
        printf("Start: waiting for connect......\n");
        if((conn = accept(sock_fd_, (struct sockaddr*)&conn_addr_, &sin_size)) == -1){
             printf("Handler: accept socket error\n");
             return; 
        }
        printf("Start: connected , recv msg......\n");
        unsigned char buffer[SERVER_DEFAULT_RECV_SIZE] = {};
        int len = 0;
        if((len = recv(conn, (void*)buffer, SERVER_DEFAULT_RECV_SIZE, 0)) <= 0){
             printf("Handler: recv msg fail\n");
             return; 
        }
        unsigned char cmd = 0xff;
        unsigned char* data = NULL;
        size_t dlen = 0;
        if(Message::MessageDecode(buffer, len, &cmd, &data, &dlen) != COMMON_SUCCESS){
             printf("Handler: MessageDecode fail\n");
             return; 
        }
        unsigned char data_[1024]={};
        memcpy(data_, data, dlen);

        Server::Wait();
        switch (cmd) {
            case 0x00:{
                std::thread t(Server::deal_with_C0, data_, dlen, conn);
                t.detach();
                break;
            }
            case 0x01:{
                std::thread t(Server::deal_with_C1, data_, dlen, conn);
                t.detach();
                break;
            }
            case 0x02:{
                std::thread t(Server::deal_with_C2, data_, dlen, conn);
                t.detach();
                break;
            }
            case 0x03:{
                std::thread t(Server::deal_with_C3, data_, dlen, conn);
                t.detach();
                break;
            }
            case 0x04:{
                std::thread t(Server::deal_with_C4, data_, dlen, conn);
                t.detach();
                break;
            }
            case 0x05:{
                std::thread t(Server::deal_with_C5, data_, dlen, conn);
                t.detach();
                break;
            }
            default:{
                printf("Handler: unknow cmd type\n");
                std::thread t(Message::SendErrorCode, conn, cmd);
                t.detach();
                break;
            }
        }

        if (data) {
            free(data);
        }
        usleep(1);
    }

}

void Server::deal_with_C0(unsigned char data[], size_t dlen, int sock){
    std::cout<<"thread deal_with_C0 statrt"<<std::endl;
    unsigned char cmd = 0x00;
    int type = (int)(*data);
    int flag = 0;
    unsigned  char* msg = NULL;
    size_t mlen = 0;
    switch (type) {
        case 1:{
            //send eca crt
            if(Message::MessageEncode(cmd, g_eca.buffer, g_eca.blen, &msg, &mlen) != COMMON_SUCCESS){
                printf("deal_with_C0: MessageEncode fail\n");
                break;
            }
            if(Message::SendMsg(sock, msg, mlen) != COMMON_SUCCESS){
                printf("deal_with_C0: SendMsg fail\n");
                free(msg);
                break;
            }
            flag = 1;
            break;
        }
        case 2:{
            //send pca crt
            if(Message::MessageEncode(cmd, g_pca.buffer, g_pca.blen, &msg, &mlen) != COMMON_SUCCESS){
                printf("deal_with_C0: MessageEncode fail\n");
                break;
            }
            if(Message::SendMsg(sock, msg, mlen) != COMMON_SUCCESS){
                printf("deal_with_C0: SendMsg fail\n");
                free(msg);
                break;
            }
            flag = 1;
            break;
        }
        case 3:{
            //send rca crt
            if(Message::MessageEncode(cmd, g_rca.buffer, g_rca.blen, &msg, &mlen) != COMMON_SUCCESS){
                printf("deal_with_C0: MessageEncode fail\n");
                break;
            }
            if(Message::SendMsg(sock, msg, mlen) != COMMON_SUCCESS){
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
    Server::Notify();
    std::cout<<"thread deal_with_C0 end"<<std::endl;
}

void Server::deal_with_C1(unsigned char data[], size_t dlen, int sock){
    std::cout<<"thread deal_with_C1 start"<<std::endl;
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

    if (Common::VerifyDeviceSerialNumber(data, dlen) != COMMON_SUCCESS) {
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

    ecrt = CertificateManage::CreateCertificate(E_CA_CRT, SubjectType_enrollmentCredential, pub_key, g_eca.hashid8, g_eca.key);
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
    Server::Notify();
    std::cout<<"thread deal_with_C1 end"<<std::endl;
}


void Server::deal_with_C2(unsigned char data[], size_t dlen, int sock){
    std::cout<<"thread deal_with_C2 start"<<std::endl;
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
    if (CertificateManage::CertificateVerify(g_eca.key, ecrt) != COMMON_SUCCESS) {
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
    Server::Notify();
    std::cout<<"thread deal_with_C2 end"<<std::endl;
}


void Server::deal_with_C3(unsigned char data[], size_t dlen, int sock){
    std::cout<<"thread deal_with_C3 start"<<std::endl;
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
    if (CertificateManage::CertificateVerify(g_eca.key, ecrt) != COMMON_SUCCESS) {
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
    Server::Notify();
    std::cout<<"thread deal_with_C3 end"<<std::endl;
}


void Server::deal_with_C4(unsigned char data[], size_t dlen, int sock){
    std::cout<<"thread deal_with_C4 start"<<std::endl;
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
    std::string name;
    if((ecrt = CertificateManage::BufferToCertificate(ecrt_buffer, ecrt_size)) == NULL){
        printf("deal_with_C4: BufferToCertificate fail\n");
        goto err;
    }
    if (CertificateManage::CertificateVerify(g_eca.key, ecrt) != COMMON_SUCCESS) {
        printf("deal_with_C4: CertificateVerify fail\n");
        goto err;
    }

    if(Common::Sm3Hash(error_crt_buffer, error_crt_size, &error_crt_hash, &error_crt_hash_size) != COMMON_SUCCESS){
        printf("deal_with_C4: Sm3Hash fail\n");
        goto err;
    }

    if((error_crt = CertificateManage::BufferToCertificate(error_crt_buffer, error_crt_size)) == NULL){
        printf("deal_with_C4: BufferToCertificate fail\n");
        goto err;
    }
//  maybe need some way to check this crt , then decide whether need to revoke it
    error_crt_end_gmtime = Common::get_time_by_diff(error_crt->validityRestrictions.choice.timeStartAndEnd.endValidity);
    error_crt_start_difftime = error_crt->validityRestrictions.choice.timeStartAndEnd.startValidity;

    error_crt_end_gmtime = Common::get_time_now();
    if ((crl = CrlManage::CreateCRL(false, error_crt_hash+32-10, error_crt_start_difftime)) == NULL) {
        printf("deal_with_C4: CreateCRL fail\n");
        goto err;
    }

    name = Common::UnsignedLongToString(error_crt_end_gmtime); 
    name = name + "_" + Common::UnsignedLongToString(crl->unsignedCrl.crlSerial);
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

    Server::Notify();
    std::cout<<"thread deal_with_C4 end"<<std::endl;
}

void Server::deal_with_C5(unsigned char data[], size_t dlen, int sock){
    std::cout<<"thread deal_with_C5 start"<<std::endl;
    int ret = COMMON_ERROR;
    unsigned char cmd = 0x03;
    Certificate_t* ecrt = NULL;
    unsigned char* crls_buffer = NULL;
    size_t crls_blen = 0;
    size_t crls_num = 0;
    int package = 0;
    unsigned char crls_package_buff[1024];
    size_t len = 0;

    if((ecrt = CertificateManage::BufferToCertificate(data, dlen)) == NULL){
        printf("deal_with_C5: BufferToCertificate fail\n");
        goto err;
    }
    if (CertificateManage::CertificateVerify(g_eca.key, ecrt) != COMMON_SUCCESS) {
        printf("deal_with_C5: CertificateVerify fail\n");
        goto err;
    }

    if(CrlManage::get_crls(&crls_buffer, &crls_blen, &crls_num) != COMMON_SUCCESS){
        printf("deal_with_C5: get_crls fail\n");
        goto err;
    }

    package = (crls_num%10 == 0)? (int)(crls_num/10) : (int)(crls_num/10)+1;
    while (package >1) {
        memcpy(crls_package_buff, crls_buffer+len, 81*10);
        len+=81*10;
        if (Message::send_crl_package(10, sock, cmd, crls_package_buff, 81*10) != COMMON_SUCCESS) {
            printf("deal_with_C5: send_crl_package fail\n");
            goto err;
        }
        package--;
        crls_num = crls_num - 10;
        usleep(1);
    }
    if (package == 1) {
        memcpy(crls_package_buff, crls_buffer+len, 81*crls_num);
        if(Message::send_crl_package(crls_num, sock, cmd, crls_package_buff, 81*crls_num) != COMMON_SUCCESS){
            printf("deal_with_C5: send_crl_package fail\n");
            goto err;
        }
    }

    ret = COMMON_SUCCESS;
    err:{
        if (crls_buffer) {
            free(crls_buffer);
        }
        if (ecrt) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Certificate, ecrt);
        }
        if (ret != COMMON_SUCCESS) {
            Message::SendErrorCode(sock, cmd);
        }
    }
    Server::Notify();
    std::cout<<"thread deal_with_C5 end"<<std::endl;
}


void Server::Notify(){
    {
        std::lock_guard<std::mutex> lck(server_mutex_);
        server_count_++;
    }
    server_condition_.notify_one();
}
 
void Server::Wait(){
    std::unique_lock<std::mutex> lck(server_mutex_);
	while(server_count_ == 0){
	    server_condition_.wait(lck);
	}
    server_count_--;
}

int main(int argc, char* argv[]) {

    if(Server::Init() != COMMON_SUCCESS){
        printf("main: Server::Init fail\n");
        return 0;
    }
    if(CertificateManage::Init() != COMMON_SUCCESS){
        printf("main: CertificateManage::Init fail\n");
        return 0;
    }
    if(CrlManage::Init() != COMMON_SUCCESS){
        printf("main: CrlManage::Init fail\n");
        return 0;
    }

    printf("main: CertificateManage::Start\n");
    CertificateManage::Start();
    printf("main: CrlManage::Start\n");
    CrlManage::Start();
    printf("main: Server::Start\n");
    Server::Start();
  
    return 0;
}
/**
* @}
**/

