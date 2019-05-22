
/***********************************************
* @addtogroup Nebula
* @{
* @file  : Message.h
* @brief :
* @date  : 2019-05-13
***********************************************/

//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------

#ifndef MESSAGE_H_
#define MESSAGE_H_

#include "CertOp.h"

#define FAIL_CODE 0x01
#define SUCC_CODE 0x00

class Message{
public:
    Message();
    ~Message();

    //need free
    static int MessageEncode(unsigned char cmd, unsigned char* data, size_t dlen, unsigned char** msg, size_t* mlen);
    static int MessageDecode(unsigned char* buffer, size_t blen, unsigned char* cmd, unsigned char** data, size_t* dlen);

    static int SendMsg(int sock, void* msg, size_t mlen);

    static unsigned char CalculateBCC(unsigned char* buff, int len);

    static int SendErrorOrSuccCode(int sock, unsigned char cmd, unsigned char code);

private:
    static unsigned char message_send_succ_code_;
    static unsigned char message_send_fail_code_;
};


#endif

/**
* @}
**/

