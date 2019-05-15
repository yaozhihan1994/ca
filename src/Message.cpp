/***********************************************
* @addtogroup Nebula
* @{
* @file  : Message.cpp
* @brief :
* @date  : 2019-04-25
***********************************************/
 
//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------
  
#include "Message.h"

using namespace std;

int DecodeMessage(unsigned char* buffer, size_t blen, unsigned char* cmd, unsigned char** data, size_t* dlen){

    if(*(buffer+blen-2) !=  BCC(buffer+2, blen-4)){
        printf("DecodeMessage: BCC() cheack Failed!\n");
        return COMMON_ERROR;
    }

    unsigned char _length[4] ={}; 
    memcpy(_length, buffer+2, 4);
    size_t len = UnsignedCharToInt(_length);
    *dlen = len - 1;
    unsigned char _cmd;
    memcpy(&_cmd, buffer+2+4, 1);
    *cmd = _cmd;
    memcpy(*data, buffer+2+4+1, *dlen);

    return COMMON_SUCCESS;
}

int sock_recv;
int sock_send;
struct sockaddr_in addr_recv;
struct sockaddr_in addr_send;

int CreateSocket(const char* ip, uint16_t port_recv, uint16_t port_send){
    
    if ((sock_recv = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        printf("CreateSocket: socket() Failed!\n");
        return COMMON_ERROR;
    } 
    bzero(&addr_recv,sizeof(struct sockaddr_in));
    addr_recv.sin_family = AF_INET;
    addr_recv.sin_addr.s_addr = INADDR_ANY; //inet_addr(ip);
    addr_recv.sin_port = htons(port_recv); 
    if ((sock_send = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        printf("CreateSocket: socket() Failed!\n");
        return COMMON_ERROR;
    } 
    bzero(&addr_send,sizeof(struct sockaddr_in));
    addr_send.sin_family = AF_INET;
    addr_send.sin_addr.s_addr = inet_addr(ip);
    addr_send.sin_port = htons(port_send); 
    int enable = 1;
    if(setsockopt(sock_recv, SOL_SOCKET, SO_REUSEADDR,  &enable, sizeof(int)) == -1){
        printf("CreateSocket: setsockopt() Failed!\n");
        return COMMON_ERROR;
    }
    if(setsockopt(sock_send, SOL_SOCKET, SO_REUSEADDR,  &enable, sizeof(int)) == -1){
        printf("CreateSocket: setsockopt() Failed!\n");
        return COMMON_ERROR;
    }
    if(::bind(sock_recv, (struct sockaddr *)&addr_recv, sizeof(struct sockaddr)) == -1){
        printf("CreateSocket: bind() Failed!\n");
        return COMMON_ERROR;
    }
    return COMMON_SUCCESS;
}

int CloseSocket(){
    return shutdown(sock_recv, SHUT_RDWR) + shutdown(sock_send, SHUT_RDWR);
}

int SendMsg(void* msg, size_t mlen){
    //encodemessage
    unsigned char buffer[mlen+1];
    memset(buffer, 0x00, 1);
    memcpy(buffer+1, msg, mlen);
    if ((sendto(sock_send, buffer, mlen+1, 0, (struct sockaddr *)&addr_send, sizeof(addr_send))) < 0){
        printf("SendMsg: Failed!\n");
        return COMMON_ERROR;
    }
    printf("send: %d\n", mlen+1);
    for (int i = 0; i<mlen; i++) {
        printf("0x%02x ", *((unsigned char*)buffer+i));
    }
    printf("\n");
    return COMMON_SUCCESS;
}

int RecvMsg(unsigned char** msg, size_t* mlen){
    memset((void* )*msg, 0, *mlen);
    int addlen = sizeof(addr_recv);
    if ((*mlen = recvfrom(sock_recv, (void* )*msg, *mlen, 0, (struct sockaddr *)&addr_recv, (socklen_t* )&addlen)) < 0){
        printf("RecvMsg: recvfrom Failed!\n");
        return COMMON_ERROR;
    }
    printf("recv: %d\n", *mlen);
    for (int i = 0; i<*mlen; i++) {
        printf("0x%02x ", *((*msg)+i));
    }
    printf("\n");
    return COMMON_SUCCESS;
}

unsigned char BCC(unsigned char* buff, int len){
    unsigned char bcc= *buff;
    for(int i=1; i<len; i++){
        bcc^=*(buff+i);
    }
    return bcc;
}

unsigned int UnsignedCharToInt(unsigned char* num){
    int ret = num[3];
    ret += num[2] << 8;
    ret += num[1] << 16;
    ret += num[0] << 24;
    return ret;
}

unsigned char* IntToUnsignedChar(unsigned int num){
    unsigned char *ret = (unsigned char* )malloc(4);
    ret[0] = num >> 24;
    ret[1] = num >> 16;
    ret[2] = num >> 8;
    ret[3] = num;
    return ret;
}

int SendCaAndKeyByFileName(const char* filename_crt, const char* filename_key){
    unsigned char *ca_buf = NULL;
    size_t ca_len = 0;
    unsigned char *key_buf = NULL;
    size_t key_len = 0;
    int ret = COMMON_ERROR;
    unsigned char *msg = NULL;
    if(FileToBuffer(filename_crt, &ca_buf, &ca_len) != COMMON_SUCCESS){
        printf("SendCaAndKeyByFileName: FileToBuffer Failed!\n");
        goto err;
    }
    if(FileToBuffer(filename_key, &key_buf, &key_len) != COMMON_SUCCESS){
        printf("SendCaAndKeyByFileName: FileToBuffer Failed!\n");
        goto err;
    }
    msg = (unsigned char*)malloc(ca_len+32);
    memcpy(msg, key_buf, 32);
    memcpy(msg +32, ca_buf, ca_len);
    if(SendMsg(msg, ca_len +32) != COMMON_SUCCESS){
        printf("SendCaAndKeyByFileName: SendMsg Failed!\n");
        goto err;
    }
    ret = COMMON_SUCCESS;
    err:{   
        if (ca_buf) {
            free(ca_buf);
        }
        if (key_buf) {
            free(key_buf);
        }
    }
    return ret;
}

int SendCaByFileName(const char* filename_crt){
    unsigned char *ca_buf = NULL;
    size_t ca_len = 0;
    int ret = COMMON_ERROR;
    if(FileToBuffer(filename_crt, &ca_buf, &ca_len) != COMMON_SUCCESS){
        printf("SendCaAndKeyByFileName: FileToBuffer Failed!\n");
        goto err;
    }

    if(SendMsg(ca_buf, ca_len) != COMMON_SUCCESS){
        printf("SendCaAndKeyByFileName: SendMsg Failed!\n");
        goto err;
    }
    ret = COMMON_SUCCESS;
    err:{   
        if (ca_buf) {
            free(ca_buf);
        }
    }
    return ret;
}

int SendErrorCode(unsigned char cmd){
    int ret = COMMON_ERROR;
    unsigned char *buffer = (unsigned char* )calloc(1024, sizeof(unsigned char));
    int blen = 0;
    memset(buffer+blen, 0xff, 2);
    blen+=2;
    unsigned char* length = IntToUnsignedChar(2);
    memcpy(buffer+blen, length, 4);
    blen+=4;
    memset(buffer+blen, cmd, 1);
    blen+=1;
    memset(buffer+blen, 0x01, 1);
    blen+=1;
    unsigned char bcc = BCC(buffer+2, 6);
    memset(buffer+blen, bcc, 1);
    blen+=1;
    memset(buffer+blen, 0xff, 1);
    blen+=1;

    if(SendMsg(buffer, blen) != COMMON_SUCCESS){
        printf("SendErrorCode: SendMsg Failed!\n");
        goto err;
    }
    ret = COMMON_SUCCESS;
    err:{
        if (length) {
            free(length);
        }
        if (buffer) {
            free(buffer);
        }
    }
    return ret;
}

int SendMsgCmdC0(int flag){
    int ret = COMMON_ERROR;
    switch (flag) {
        case 1:{
            printf("SendMsgCmdC0: send eca crt !\n");
            if(SendCaByFileName(ECACRT) != COMMON_SUCCESS){
                printf("SendMsgCmdC0: SendCaByFileName ECACRT Failed!\n");
                break;
            }
            ret = COMMON_SUCCESS;
            break;
        }
         case 2:{
            printf("SendMsgCmdC0: send pca crt !\n");
            if(SendCaByFileName(PCACRT) != COMMON_SUCCESS){
                printf("SendMsgCmdC0: SendCaByFileName PCACRT Failed!\n");
                break;
            }
            ret = COMMON_SUCCESS;
            break;
        }
        case 3:{
            printf("SendMsgCmdC0: send pca crt !\n");
            if(SendCaByFileName(RCACRT) != COMMON_SUCCESS){
                printf("SendMsgCmdC0: SendCaByFileName RCACRT Failed!\n");
                break;
            }
            ret = COMMON_SUCCESS;
            break;
        }
        default:break;
    }
    return ret;
}

int CheckID(unsigned char* id, size_t ilen){
    fstream fs(DEVICE_SERIAL_NUMBER);
    if (!fs) {
        printf("CheckID: open file: %s Failed!\n", DEVICE_SERIAL_NUMBER);
        return COMMON_ERROR;
    }
    unsigned char sn[81];
    while (fs.peek() != EOF) {
        fs.getline(sn, 81);
//      cout<<sn<<endl;
        if(memcmp(id, sn, ilen) == 0){
            return COMMON_SUCCESS;
        }
    }
    fs.close();
    return COMMON_ERROR;
}


int CheckECA(EC_KEY* key, unsigned char* ca, size_t clen){
    if (!ca) {
        return COMMON_NULL_POINT;
    }
    int ret = COMMON_ERROR;
    Certificate_t* crt = 0;
    crt = BufferToCertificate(ca, clen);
    if (!crt) {
        printf("CheckECA: BufferToCertificate Failed!\n");
        goto err;
    }

    if (CertificateVerify(key, crt) != COMMON_SUCCESS) {
        printf("CheckECA: CertificateVerify Failed!\n");
        goto err;
    }

    ret = COMMON_SUCCESS;
    err:{
        if (crt) {
            ASN_STRUCT_FREE(asn_DEF_Certificate, crt);
        }
    }
    return ret;
}


int set_crl_serial_number(unsigned long sn){
    fstream fs;
    fs.open(CRL_SERIAL_NUMBER, ios::out);
    if (!fs) {
        printf("set_crl_serial_number: open file: %s Failed!\n", CRL_SERIAL_NUMBER);
        return COMMON_ERROR;
    }
    fs<<sn;
    fs.close();
}
