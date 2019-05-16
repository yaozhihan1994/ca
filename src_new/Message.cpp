
/***********************************************
* @addtogroup Nebula
* @{
* @file  : Message.cpp
* @brief :
* @date  : 2019-05-13
***********************************************/

//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------

#include "Common.h"
#include "Message.h"

using namespace MESSAGE;

unsigned char Message::message_send_succ_code = SUCC_CODE;
unsigned char Message::message_send_fail_code = FAIL_CODE;

Message::Message(){
}

Message::~Message(){
}

int Mesage::MessageEncode(unsigned char cmd, unsigned char* data, size_t dlen, unsigned char** msg, size_t* mlen){

    unsigned char* msg_ = (unsigned char* )malloc(dlen + 10);
    if (!msg_) {
        printf("MessageEncode: malloc msg fail\n");
        return COMMON_ERROR;
    }
    int len = 0;
    memset(msg_+len, 0xff, 2);
    len+=2;
    unsigned int length = 2+dlen;
    unsigned char* length_ = Common::IntToUnsignedChar(length);
    if (!length_) {
        printf("MessageEncode: IntToUnsignedChar fail\n");
        return COMMON_ERROR;
    }
    memcpy(msg_+len, length_, 4);
    len+=4;
    memset(msg_+len, cmd, 1);
    len+=1;
    memset(msg_+len, Message::message_send_succ_code, 1);
    len+=1;
    memcpy(msg_+len, data, dlen);
    len+=dlen;
    unsigned char bcc = Message::CalculateBCC(msg_+2, len-2);
    memcpy(msg_+len, bcc, 1);
    len+=1;
    memset(msg_+len, 0xff, 1);
    len+=1;

    *msg = msg_;
    *mlen = len;
    free(length_);
    return COMMON_SUCCESS;
}

int Mesage::MessageDecode(unsigned char* buffer, size_t blen, unsigned char* cmd, unsigned char** data, size_t* dlen){
    unsigned char head[2] = {0xff,0xff};
    if (memcmp(buffer, head, 2) != 0) {
        printf("MessageDecode verify msg head fail\n");
        return COMMON_ERROR;
    }
    if(*(buffer+blen-2) !=  Message::CalculateBCC(buffer+2, blen-4)){
        printf("MessageDecode:  cheack bcc Failed!\n");
        return COMMON_ERROR;
    }
    unsigned char length[4];
    memcpy(length, buffer+2, 4);
    unsigned int length_ = Common::UnsignedCharToInt(length);
    *dlen = length_-1;
    unsigned char* data_ = (unsigned char*)malloc(*dlen);
    if (!data_) {
        printf("MessageDecode malloc data_ fail\n");
        return COMMON_ERROR;
    }
    unsigned char cmd_;
    memcpy(&cmd_, buffer+2+4, 1);
    *cmd = cmd_;

    memcpy(data_, buffer+7, *dlen);
    *data = data_;
    return COMMON_SUCCESS;
}

int Message::SendMsg(int sock, void* msg, size_t mlen){
    if(send(sock, msg, mlen, 0) == -1){
        printf("SendMsg fail\n");
        return COMMON_ERROR;
    }
    return COMMON_SUCCESS;
}

unsigned char Message::CalculateBCC(unsigned char* buff, int len){
    unsigned char bcc= *buff;
    for(int i=1; i<len; i++){
        bcc^=*(buff+i);
    }
    return bcc;
}


int Mesage::SendErrorCode(int sock, unsigned char cmd){
    int ret = COMMON_ERROR;
    unsigned char data = FAIL_CODE;
    unsigned char* msg = NULL;
    size_t meln = 0;
    if(Message::MessageEncode(cmd, (unsigned char* )&data, 1, &msg, &mlen) != COMMON_SUCCESS){
        printf("SendErrorCode: MessageEncode fail\n");
        goto err; 
    }
    if(Message::SendMsg(sock, (void* )msg, mlen) != COMMON_SUCCESS){
        printf("SendErrorCode: SendMsg fail\n");
        goto err; 
    }

    ret = COMMON_SUCCESS;
    err:{
        if(msg){
            free(msg);
        }
    }
    return ret;
}

/**
* @}
**/

