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

        const char* ca_crt_filename = "crts";
        const char* pcrt_filename = "pcrts";
        const char* rcrt_filename = "rcrts";    
        const char* crl_filename = "crls";
        const char* serial_number_filename = "serial_number";
        if (access(ca_crt_filename, F_OK) == -1) {
            if (mkdir(ca_crt_filename, 493) == -1) {
                return COMMON_ERROR;
            }
        }
        if (access(pcrt_filename, F_OK) == -1) {
            if (mkdir(pcrt_filename, 493) == -1) {
                return COMMON_ERROR;
            }
        }
        if (access(rcrt_filename, F_OK) == -1) {
            if (mkdir(rcrt_filename, 493) == -1) {
                return COMMON_ERROR;
            }
        }
        if (access(crl_filename, F_OK) == -1) {
            if (mkdir(crl_filename, 493) == -1) {
                return COMMON_ERROR;
            }
        }
        if (access(serial_number_filename, F_OK) == -1) {
            if (mkdir(serial_number_filename, 493) == -1) {
                return COMMON_ERROR;
            }
        }
        if (access(CRL_SERIAL_NUMBER, F_OK) == -1) {
            std::fstream fs;
            fs.open(CRL_SERIAL_NUMBER, std::fstream::out);
            if (!fs) {
                printf("Init: create file: %s Failed!\n", CRL_SERIAL_NUMBER);
                return COMMON_ERROR;
            }
            fs<<0;
            fs.close();
        }
        if (access(DEVICE_SERIAL_NUMBER, F_OK) == -1) {
            std::fstream fs;
            fs.open(DEVICE_SERIAL_NUMBER, std::fstream::out);
            if (!fs) {
                printf("Init: create file: %s Failed!\n", DEVICE_SERIAL_NUMBER);
                return COMMON_ERROR;
            }
            fs<<DEFAULT_DEVICE_SERIAL_NUMBER;
            fs.close();
        }

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
    if (NULL == ca) {
        printf("init_ca: COMMON_INVALID_PARAMS\n");
        return COMMON_INVALID_PARAMS;
    }
    ca->key = CertOp::FileToKey(key_filename.c_str());
    if (ca->key == NULL) {
        printf("init_ca FileToKey: %s fail\n", key_filename.c_str());
        return COMMON_ERROR;
    }
    ca->crt = CertMng::FileToCertificate(crt_filename.c_str());
    if (ca->crt == NULL) {
        printf("init_ca FileToCertificate: %s fail\n", crt_filename.c_str());
        return COMMON_ERROR;
    }
    if (CertMng::CertificateToBuffer(&(ca->buffer), &(ca->blen), ca->crt) != COMMON_SUCCESS) {
        printf("init_ca CertificateToBuffer: %s fail\n", crt_filename.c_str());
        return COMMON_ERROR;
    }
    unsigned char* der_buffer = NULL;
    size_t dlen = 0;
    if (CertMng::CertificateToDer(&der_buffer, &dlen, ca->crt) != COMMON_SUCCESS) {
        printf("init_ca CertificateToDer: %s fail\n", crt_filename.c_str());
        return COMMON_ERROR;
    }
    unsigned char* hash = NULL;
    size_t hlen = 0;
    if (CertOp::Sm3Hash(der_buffer, dlen, &hash, &hlen) != COMMON_SUCCESS) {
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
    free(der_buffer);
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

    if (ctype != ROOT_CA_CRT && (!sign_crt_hashid8 || !sign_key)) {
        return COMMON_INVALID_PARAMS;
    }
    int ret = COMMON_ERROR;
    EC_KEY* key = NULL;
    Certificate_t* crt = NULL;
    unsigned char* pub_key = NULL;
    unsigned char* hash = NULL;
    size_t hlen = 0;
    unsigned char* hashid8 = NULL;
    unsigned char* der_buffer = NULL;
    size_t dlen = 0;
    key = CertOp::CreateSm2KeyPair();
    if (!key) {
        printf("create_ca_to_file CreateSm2KeyPair fail\n");
        goto err;
    }
    pub_key = CertOp::get_sm2_public_key(key);
    if (!pub_key) {
        printf("create_ca_to_file get_sm2_public_key fail\n");
        goto err;
    }

    if (ctype == ROOT_CA_CRT) {
        crt = CertMng::CreateCertificate(ctype, stype, pub_key, NULL, key);
    }else{
        crt = CertMng::CreateCertificate(ctype, stype, pub_key, sign_crt_hashid8, sign_key);
    }

    if (!crt) {
        printf("create_ca_to_file CreateCertificate crt fail\n");
        goto err;
    }

    if(CertMng::CertificateToFile(crt_filename.c_str(), crt) !=COMMON_SUCCESS){
        printf("create_ca_to_file CertificateToFile fail\n");
        goto err;
    }

    if(CertOp::KeyToFile(key_filename.c_str(), key) != COMMON_SUCCESS){
        printf("create_ca_to_file KeyToFile fail\n");
        goto err;
    }

    if (CertMng::CertificateToBuffer(&(ca->buffer), &(ca->blen), crt) != COMMON_SUCCESS) {
        printf("create_ca_to_file CertificateToBuffer: %s fail\n", crt_filename.c_str());
        goto err;
    }

    if (CertMng::CertificateToDer(&der_buffer, &dlen, crt) != COMMON_SUCCESS) {
        printf("create_ca_to_file CertificateToDer: %s fail\n", crt_filename.c_str());
        goto err;
    }

    if (CertOp::Sm3Hash(der_buffer, dlen, &hash, &hlen) != COMMON_SUCCESS) {
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
        if (der_buffer) {
            free(der_buffer);
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
        Server::Wait();
        struct sockaddr_in conn_addr_;
        int sin_size = sizeof(struct sockaddr_in);
        int conn = 0;
        printf("Start: waiting for connect......\n");
        if((conn = accept(sock_fd_, (struct sockaddr*)&conn_addr_, (socklen_t*)&sin_size)) == -1){
             printf("Handler: accept socket error\n");
             return; 
        }
        std::thread t(Server::Handler, conn, conn_addr_);
        t.detach();
//      t.join();
        usleep(1);
    }

}

void Server::Handler(int sock, struct sockaddr_in addr){
    printf("Handler: connected , recv msg......\n");
    unsigned char buffer[SERVER_DEFAULT_RECV_SIZE] = {};
    int len = 0;
    struct timeval timeout={3,0};//3s
    int ret=setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(const char*)&timeout,sizeof(timeout));
    if (ret == -1) {
         printf("Handler: setsockopt fail\n");
         return;
    }
    while (true) {
        if ((len = recv(sock, (void *)buffer, SERVER_DEFAULT_RECV_SIZE, 0)) <= 0) {
            printf("Handler: recv msg timeout\n");
            break;
        }
	printf("recv: %d\n",len);
	CertOp::print_buffer(buffer,len);
        unsigned char cmd = 0xff;
        unsigned char* data = NULL;
        int result = COMMON_ERROR;
        size_t dlen = 0;
        printf("Handler: recv msg suc , message decoding......\n");
        if(Message::MessageDecode(buffer, len, &cmd, &data, &dlen) != COMMON_SUCCESS){
             printf("Handler: MessageDecode fail\n");
             return; 
        }
        printf("Handler: recv msg suc , message decoded succ cmd: 0x%02x\n", cmd);
        if (dlen == 0) {
            printf("Handler: dlen = 0\n");
            continue ;
        }
        //maybe use thead , but if recv too many msg it will have many thread 
        switch (cmd) {
            case 0xc0:{
                result = Server::deal_with_C0(data, dlen, sock);
                break;
            }
            case 0xc1:{
                result = Server::deal_with_C1(data, dlen, sock);
                break;
            }
            case 0xc2:{
                result = Server::deal_with_C2(data, dlen, sock);
                break;
            }
            case 0xc3:{
                result = Server::deal_with_C3(data, dlen, sock);
                break;
            }
            case 0xc4:{
                result = Server::deal_with_C4(data, dlen, sock);
                break;
            }
            case 0xc5:{
                result = Server::deal_with_C5(data, dlen, sock);
                break;
            }
            case 0xc6:{
                result = Server::deal_with_C6(data, dlen, sock);
                break;
            }
            default:{
                printf("Handler: unknow cmd type\n");
                break;
            }
        }
        if (data) {
            free(data);
        }
        if (result != COMMON_SUCCESS) {
            if(Message::SendErrorOrSuccCode(sock, cmd, 0x01) != COMMON_SUCCESS){
                printf("Handler: SendErrorCode fail\n");
                break;
            }
        }
        usleep(1);
    }
    close(sock);
    Server::Notify();
    printf("Handler: end\n");
}

int Server::deal_with_C0(unsigned char* data, size_t dlen, int sock){
    std::cout<<"thread deal_with_C0 statrt"<<std::endl;
    if (NULL == data || 0 > sock) {
        printf("deal_with_C0: COMMON_INVALID_PARAMS\n");
        return COMMON_INVALID_PARAMS;
    }
    unsigned char cmd = 0xc0;
    int ret = COMMON_ERROR; 
    unsigned char type = (*data);
    int flag = 0;
    unsigned  char* msg = NULL;
    size_t mlen = 0;
    unsigned char buffer[CERT_LENGTH+1];
    size_t blen = CERT_LENGTH+1;
    memset(buffer, type, 1);
    switch (type) {
        case 0x01:{
            //send eca crt
            printf("deal_with_C0: send eca crt\n");
            memcpy(buffer+1, g_eca.buffer, g_eca.blen);
            break;
        }
        case 0x02:{
            //send pca crt      
            printf("deal_with_C0: send pca crt\n");
            memcpy(buffer+1, g_pca.buffer, g_pca.blen);
            break;
        }
        case 0x03:{
            //send rca crt
            printf("deal_with_C0: send rca crt\n");
            memcpy(buffer+1, g_rca.buffer, g_rca.blen);
            break;
        }
        case 0x04:{
            //send cca crt
            printf("deal_with_C0: send cca crt\n");
            memcpy(buffer+1, g_cca.buffer, g_cca.blen);
            break;
        }
        default:{
            printf("deal_with_C0: unknow request ca crt type\n");
            break;
        }
    }

    if((ret = Message::MessageEncode(cmd, buffer, blen, &msg, &mlen)) != COMMON_SUCCESS){
        printf("deal_with_C0: MessageEncode fail\n");
        goto err;
    }
    if((ret = Message::SendMsg(sock, msg, mlen)) != COMMON_SUCCESS){
        printf("deal_with_C0: SendMsg fail\n");
        goto err;
    }

    ret = COMMON_SUCCESS;
    err:{
        if (msg) {
            free(msg);
        }
    }
    std::cout<<"thread deal_with_C0 end"<<std::endl;
    return ret;
}

int Server::deal_with_C1(unsigned char* data, size_t dlen, int sock){
    std::cout<<"thread deal_with_C1 start"<<std::endl;
    if (NULL == data || 0 > sock) {
        printf("deal_with_C1: COMMON_INVALID_PARAMS\n");
        return COMMON_INVALID_PARAMS;
    }
    int ret = COMMON_ERROR;
    unsigned char cmd = 0xc1;
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

    if (CertOp::VerifyDeviceSerialNumber((char* )data, dlen) != COMMON_SUCCESS) {
        printf("deal_with_C1: VerifyDeviceSerialNumber fail\n");
        goto err;
    }
    key = CertOp::CreateSm2KeyPair();
    if (!key) {
        printf("deal_with_C1: CreateSm2KeyPair fail\n");
        goto err;
    }
    pub_key = CertOp::get_sm2_public_key(key);
    if (!pub_key) {
        printf("deal_with_C1: get_sm2_public_key fail\n");
        goto err;
    }
    pri_key = CertOp::get_sm2_private_key(key);
    if (!pri_key) {
        printf("deal_with_C1: get_sm2_private_key fail\n");
        goto err;
    }

    ecrt = CertMng::CreateCertificate(E_CA_CRT, SubjectType_enrollmentCredential, pub_key, g_eca.hashid8, g_eca.key);
    if (!ecrt) {
        printf("deal_with_C1: CreateCertificate ecrt fail\n");
        goto err;
    }

    //printf("deal_with_C1: sig   %d\n", ecrt->signature.choice.signature.size );
    //CertOp::print_buffer(ecrt->signature.choice.signature.buf, ecrt->signature.choice.signature.size);

    if (CertMng::CertificateToBuffer(&ecrt_buffer, &ecrt_buffer_size, ecrt) != COMMON_SUCCESS) {
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
    }
    std::cout<<"thread deal_with_C1 end"<<std::endl;
    return ret;
}


int Server::deal_with_C2(unsigned char* data, size_t dlen, int sock){
    std::cout<<"thread deal_with_C2 start"<<std::endl;
    if (NULL == data || 0 > sock || dlen < CERT_LENGTH) {
        printf("deal_with_C2: COMMON_INVALID_PARAMS\n");
        return COMMON_INVALID_PARAMS;
    }

    int ret = COMMON_ERROR;
    unsigned char cmd = 0xc2;
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
    if((ecrt = CertMng::BufferToCertificate(data, dlen)) == NULL){
        printf("deal_with_C2: BufferToCertificate fail\n");
        goto err;
    }
    if (CertMng::CertificateVerify(g_eca.key, ecrt) != COMMON_SUCCESS) {
        printf("deal_with_C2: CertificateVerify fail\n");
        goto err;
    }

    if(CertMng::get_pcrt_and_pkey(&crt_buffer, &crt_buffer_size, &key_buffer, &key_buffer_size) != COMMON_SUCCESS){
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
    }
    std::cout<<"thread deal_with_C2 end"<<std::endl;
    return ret;
}


int Server::deal_with_C3(unsigned char* data, size_t dlen, int sock){
    std::cout<<"thread deal_with_C3 start"<<std::endl;
    if (NULL == data || 0 > sock || dlen < CERT_LENGTH) {
        printf("deal_with_C3: COMMON_INVALID_PARAMS\n");
        return COMMON_INVALID_PARAMS;
    }
    int ret = COMMON_ERROR;
    unsigned char cmd = 0xc3;
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
    if((ecrt = CertMng::BufferToCertificate(data, dlen)) == NULL){
        printf("deal_with_C3: BufferToCertificate fail\n");
        goto err;
    }
    if (CertMng::CertificateVerify(g_eca.key, ecrt) != COMMON_SUCCESS) {
        printf("deal_with_C3: CertificateVerify fail\n");
        goto err;
    }

    if(CertMng::get_rcrt_and_rkey(&crt_buffer, &crt_buffer_size, &key_buffer, &key_buffer_size)){
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
    }
    std::cout<<"thread deal_with_C3 end"<<std::endl;
    return ret;
}

int Server::deal_with_C4(unsigned char* data, size_t dlen, int sock){
    std::cout<<"thread deal_with_C4 start"<<std::endl;
    if (NULL == data || 0 > sock || dlen < CERT_LENGTH*2 +1) {
        printf("deal_with_C4: COMMON_INVALID_PARAMS\n");
        return COMMON_INVALID_PARAMS;
    }
    int ret = COMMON_ERROR;
    unsigned char cmd = 0xc4;
    unsigned char error_crt_type = *data;
    size_t error_crt_size = CERT_LENGTH;
    unsigned char error_crt_buffer[error_crt_size];
    memcpy(error_crt_buffer, data + 1, error_crt_size);
    size_t ecrt_size = CERT_LENGTH;
    unsigned char ecrt_buffer[ecrt_size];
    memcpy(ecrt_buffer, data+error_crt_size+1, ecrt_size);
    Certificate_t* error_crt = NULL;
    Certificate_t* ecrt = NULL;
    EC_KEY* error_crt_verify_key = NULL;
    unsigned char* error_crt_hash = NULL;
    size_t error_crt_hash_size = 0;
    size_t error_crt_end_gmtime = 0;
    size_t error_crt_start_difftime = 0;
    Crl_t* crl = NULL;
    std::string name;
    unsigned char* der_buffer = NULL;
    size_t der_len = 0;
    if((ecrt = CertMng::BufferToCertificate(ecrt_buffer, ecrt_size)) == NULL){
        printf("deal_with_C4: BufferToCertificate fail\n");
        goto err;
    }
    if (CertMng::CertificateVerify(g_eca.key, ecrt) != COMMON_SUCCESS) {
        printf("deal_with_C4: CertificateVerify fail\n");
        goto err;
    }

    if((error_crt = CertMng::BufferToCertificate(error_crt_buffer, error_crt_size)) == NULL){
        printf("deal_with_C4: BufferToCertificate fail\n");
        goto err;
    }

    switch (error_crt_type) {
        case 0x02:{
            error_crt_verify_key = g_pca.key;
            break;
        }
        case 0x03:{
            error_crt_verify_key = g_rca.key;
            break;
        }
        default:{
            printf("deal_with_C4: unknow error_crt_type\n");
            break;
        }
    }
    if (error_crt_verify_key == NULL) {
        printf("deal_with_C4: error_crt_verify_key NULL\n");
        goto err;
    }

    if (CertMng::CertificateVerify(error_crt_verify_key, error_crt) != COMMON_SUCCESS) {
        printf("deal_with_C4deal_with_C4: CertificateVerify fail\n");
        goto err;
    }

    if (CertMng::CertificateToDer(&der_buffer, &der_len, error_crt) != COMMON_SUCCESS) {
        printf("deal_with_C4 CertificateToDer fail\n");
        goto err;
    }

    if(CertOp::Sm3Hash(der_buffer, der_len, &error_crt_hash, &error_crt_hash_size) != COMMON_SUCCESS){
        printf("deal_with_C4: Sm3Hash fail\n");
        goto err;
    }
//  maybe need some way to check this crt , then decide whether need to revoke it
    error_crt_end_gmtime = CertOp::get_time_by_diff(error_crt->validityRestrictions.choice.timeStartAndEnd.endValidity);
    error_crt_start_difftime = error_crt->validityRestrictions.choice.timeStartAndEnd.startValidity;

    if ((crl = CRLMng::CreateCRL(false, error_crt_hash+32-10, error_crt_start_difftime)) == NULL) {
        printf("deal_with_C4: CreateCRL fail\n");
        goto err;
    }

    name = CertOp::UnsignedLongToString(error_crt_end_gmtime);
    name = name + "_" + CertOp::UnsignedLongToString(crl->unsignedCrl.crlSerial);

    CRLMng::set_crl_map(name, error_crt_hash+32-10);
    name =  CRL_FILENAME+name;

    if (CRLMng::CrlToFile(name.c_str(), crl) != COMMON_SUCCESS) {
        printf("deal_with_C4: CrlToFile fail\n");
        goto err;
    }

    if (Message::SendErrorOrSuccCode(sock, cmd, 0x00) != COMMON_SUCCESS) {
        printf("deal_with_C4: SendErrorOrSuccCode fail\n");
        goto err;
    }
    printf("deal_with_C4: report error crt succ\n");

    ret = COMMON_SUCCESS;
    err:{
        if (error_crt_hash) {
            free(error_crt_hash);
        }
        if (der_buffer) {
            free(der_buffer);
        }
        if (ecrt) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Certificate, ecrt);
        }
        if (error_crt) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Certificate, error_crt);
        }
        if (crl) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Crl, crl);
        }
    }
    std::cout<<"thread deal_with_C4 end"<<std::endl;
    return ret;
}

int Server::deal_with_C5(unsigned char* data, size_t dlen, int sock){
    std::cout<<"thread deal_with_C5 start"<<std::endl;
    if (NULL == data || 0 > sock || dlen < CERT_LENGTH) {
        printf("deal_with_C5: COMMON_INVALID_PARAMS\n");
        return COMMON_INVALID_PARAMS;
    }
    int ret = COMMON_ERROR;
    int i;
    unsigned char cmd = 0xc5;
    Certificate_t* ecrt = NULL;
    unsigned char* crls_buffer = NULL;
    size_t crls_blen = 0;
    size_t crls_num = 0;
    int package = 0;
    unsigned char *package_uc = NULL;
    unsigned char crls_package_buff[10*CRL_MAX_LENGTH + 4];
    int package_sum = 0;
    unsigned char *package_sum_uc = NULL;
    size_t crl_buff_tmp = 0; 
    size_t crl_pack_tmp = 0; 
    size_t num = 0; 
    unsigned char* msg = NULL;
    size_t mlen = 0;

    if((ecrt = CertMng::BufferToCertificate(data, dlen)) == NULL){
        printf("deal_with_C5: BufferToCertificate fail\n");
        goto err;
    }
    if (CertMng::CertificateVerify(g_eca.key, ecrt) != COMMON_SUCCESS) {
        printf("deal_with_C5: CertificateVerify fail\n");
        goto err;
    }

    if(CRLMng::get_crls(&crls_buffer, &crls_blen, &crls_num) != COMMON_SUCCESS){
        printf("deal_with_C5: get_crls fail\n");
        goto err;
    }

//  CertOp::print_buffer(crls_buffer, crls_blen);

    package = (crls_num%10 == 0)? (int)(crls_num/10) : (int)(crls_num/10)+1;
    package_sum = package;
    package_sum_uc = CertOp::IntToUnsignedChar(package_sum);
    if (!package_sum_uc) {
        printf("deal_with_C5: IntToUnsignedChar fail\n");
        goto err;
    }

    while (package > 0) {
        memcpy(crls_package_buff+crl_pack_tmp, package_sum_uc + 2, 2);
        crl_pack_tmp+=2;
        package_uc = CertOp::IntToUnsignedChar(package);
        if (!package_uc) {
            printf("deal_with_C5: IntToUnsignedChar fail\n");
            goto err;
        }
        memcpy(crls_package_buff+crl_pack_tmp, package_uc + 2, 2);
        crl_pack_tmp+=2;
        free(package_uc);

        if (package != 1) num =10;
        else num = crls_num;

        for (i = 0; i<num; i++) {
            memcpy(crls_package_buff + crl_pack_tmp, crls_buffer + crl_buff_tmp, CRL_MAX_LENGTH);
            crl_buff_tmp+=CRL_MAX_LENGTH;
            crl_pack_tmp+=CRL_MAX_LENGTH;
        }

        if (Message::MessageEncode(cmd, crls_package_buff, crl_pack_tmp, &msg, &mlen) != COMMON_SUCCESS) {
            printf("deal_with_C5: MessageEncode crls_package_buff fail\n");
            goto err;
        }
        if (Message::SendMsg(sock, msg, mlen) != COMMON_SUCCESS) {
            printf("deal_with_C5: SendMsg fail\n");
            goto err;
        }
        free(msg);
        crl_pack_tmp = 0;
        package--;
        crls_num = crls_num - num;
        usleep(1);
    }

    ret = COMMON_SUCCESS;
    err:{
        if (crls_buffer) {
            free(crls_buffer);
        }
        if (package_sum_uc) {
            free(package_sum_uc);
        }
        if (ecrt) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Certificate, ecrt);
        }
    }
    std::cout<<"thread deal_with_C5 end"<<std::endl;
    return ret;
}


int Server::deal_with_C6(unsigned char* data, size_t dlen, int sock){
    std::cout<<"thread deal_with_C6 start"<<std::endl;
    if (NULL == data || 0 > sock || dlen < CERT_LENGTH*2 +1) {
        printf("deal_with_C6: COMMON_INVALID_PARAMS\n");
        return COMMON_INVALID_PARAMS;
    }
    int ret = COMMON_ERROR;
    unsigned char cmd = 0xc6;
    unsigned char error_crt_type = *data;
    size_t error_crt_size = CERT_LENGTH;
    unsigned char error_crt_buffer[error_crt_size];
    memcpy(error_crt_buffer, data + 1, error_crt_size);
    size_t ecrt_size = CERT_LENGTH;
    unsigned char ecrt_buffer[ecrt_size];
    memcpy(ecrt_buffer, data+error_crt_size+1, ecrt_size);
    Certificate_t* error_crt = NULL;
    Certificate_t* ecrt = NULL;
    EC_KEY* error_crt_verify_key = NULL;
    unsigned char* error_crt_hash = NULL;
    size_t error_crt_hash_size = 0;
    std::string name;
    unsigned char check_result = 0xff;
    unsigned char* der_buffer = NULL;
    size_t der_len = 0;
    if((ecrt = CertMng::BufferToCertificate(ecrt_buffer, ecrt_size)) == NULL){
        printf("deal_with_C6: BufferToCertificate fail\n");
        goto err;
    }
    if (CertMng::CertificateVerify(g_eca.key, ecrt) != COMMON_SUCCESS) {
        printf("deal_with_C6: CertificateVerify fail\n");
        goto err;
    }

    if((error_crt = CertMng::BufferToCertificate(error_crt_buffer, error_crt_size)) == NULL){
        printf("deal_with_C6: BufferToCertificate fail\n");
        goto err;
    }

    switch (error_crt_type) {
        case 0x02:{
            error_crt_verify_key = g_pca.key;
            break;
        }
        case 0x03:{
            error_crt_verify_key = g_rca.key;
            break;
        }
        default:{
            printf("deal_with_C6: unknow error_crt_type\n");
            break;
        }
    }
    if (error_crt_verify_key == NULL) {
        printf("deal_with_C6: error_crt_verify_key NULL\n");
        goto err;
    }

    if (CertMng::CertificateVerify(error_crt_verify_key, error_crt) != COMMON_SUCCESS) {
        printf("deal_with_C6: CertificateVerify fail\n");
        goto err;
    }

    if (CertMng::CertificateToDer(&der_buffer, &der_len, error_crt) != COMMON_SUCCESS) {
        printf("deal_with_C6 CertificateToDer fail\n");
        goto err;
    }

    if(CertOp::Sm3Hash(der_buffer, der_len, &error_crt_hash, &error_crt_hash_size) != COMMON_SUCCESS){
        printf("deal_with_C6: Sm3Hash fail\n");
        goto err;
    }

//  check if error crt is in crl list
    if (CRLMng::check_reported_crl(error_crt_hash+32-10) == COMMON_SUCCESS) {
        check_result = 0x00;
        printf("deal_with_C6: reported crl exist\n");
    }else{
        check_result = 0x01;
        printf("deal_with_C6: reported crl no exist\n");
    }

//messageencode + send
    if (Message::SendErrorOrSuccCode(sock, cmd, 0x00) != COMMON_SUCCESS) {
        printf("deal_with_C6: SendErrorOrSuccCode fail\n");
        goto err;
    }

    ret = COMMON_SUCCESS;
    err:{
        if (error_crt_hash) {
            free(error_crt_hash);
        }
        if (der_buffer) {
            free(der_buffer);
        }
        if (ecrt) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Certificate, ecrt);
        }
        if (error_crt) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Certificate, error_crt);
        }
    }
    std::cout<<"thread deal_with_C6 end"<<std::endl;
    return ret;
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
    if(CertMng::Init() != COMMON_SUCCESS){
        printf("main: CertMng::Init fail\n");
        return 0;
    }
    if(CRLMng::Init() != COMMON_SUCCESS){
        printf("main: CRLMng::Init fail\n");
        return 0;
    }

//  unsigned char* buff = NULL;
//  size_t blen = 0;

//  CertMng::CertificateToDer(&buff, &blen, g_eca.crt);
//  printf("crt %d\n",blen);
//  CertOp::print_buffer(buff, blen);
//
//  Certificate_t* c = CertMng::DerToCertificate(buff, blen);
//  xer_fprint(stdout, &asn_DEF_Certificate, c);


    printf("main: CertMng::Start\n");
    CertMng::Start();
    printf("main: CRLMng::Start\n");
    CRLMng::Start();
    printf("main: Server::Start\n");
    Server::Start();
}



/**
* @}
**/

