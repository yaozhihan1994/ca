/***********************************************
* @addtogroup Nebula
* @{
* @file  : Message.h
* @brief :
* @date  : 2019-04-25
***********************************************/

//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------


#ifndef MESSAGE_H_
#define MESSAGE_H_
#include "Init.h"
#include "Common.h"
#include "CertificateAndCrl.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>

#define IP_HOST "127.0.0.1"
#define PORT_RECV 6666
#define PORT_SEND 8888

int DecodeMessage(unsigned char* buffer, size_t blen, unsigned char* cmd, unsigned char** data, size_t* dlen);
int CreateSocket(const char* ip, uint16_t port_recv, uint16_t port_send);
int CloseSocket();
int SendMsg(void* msg, size_t mlen);
int RecvMsg(unsigned char** msg, size_t* mlen);
unsigned char BCC(unsigned char* buff, int len);

unsigned int UnsignedCharToInt(unsigned char* num);
unsigned char* IntToUnsignedChar(unsigned int num);

int SendCaAndKeyByFileName(const char* filename_crt, const char* filename_key);
int SendCaByFileName(const char* filename_crt);
int SendErrorCode(unsigned char cmd);
int SendMsgCmdC0(int flag);
int CheckID(unsigned char* id, size_t ilen);

int CheckECA(EC_KEY* key, unsigned char* ca, size_t clen);

int set_crl_serial_number(unsigned long sn);
#endif

/**
* @}
**/



