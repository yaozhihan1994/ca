
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

#include "Message.h"

unsigned char Message::message_send_succ_code_ = SUCC_CODE;
unsigned char Message::message_send_fail_code_ = FAIL_CODE;

Message::Message(){
}

Message::~Message(){
}

int Message::MessageEncode(unsigned char cmd, unsigned char* data, size_t dlen, unsigned char** msg, size_t* mlen){
    if (data == NULL) {
        return COMMON_INVALID_PARAMS;
    }
    unsigned char *msg_ = (unsigned char *)malloc(dlen + 10);
    if (!msg_) {
        printf("MessageEncode: malloc msg fail\n");
        return COMMON_ERROR;
    }
    int len = 0;
    memset(msg_+len, 0xff, 2);
    len+=2;
    unsigned int length = 2+dlen;
    unsigned char* length_ = CertOp::IntToUnsignedChar(length);
    if (!length_) {
        printf("MessageEncode: IntToUnsignedChar fail\n");
        return COMMON_ERROR;
    }
    memcpy(msg_+len, length_, 4);
    len+=4;
    memset(msg_+len, cmd, 1);
    len+=1;
    memset(msg_+len, Message::message_send_succ_code_, 1);
    len+=1;
    memcpy(msg_+len, data, dlen);
    len+=dlen;
    unsigned char bcc = Message::CalculateBCC(msg_+2, len-2);
    memset(msg_+len, bcc, 1);
    len+=1;
    memset(msg_+len, 0xff, 1);
    len+=1;
    *msg = msg_;
    *mlen = len;
    free(length_);
    return COMMON_SUCCESS;
}

int Message::MessageDecode(unsigned char* buffer, size_t blen, unsigned char* cmd, unsigned char** data, size_t* dlen){
    if (buffer == NULL) {
        return COMMON_INVALID_PARAMS;
    }

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
    unsigned int length_ = CertOp::UnsignedCharToInt(length);
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
    if (msg == NULL || sock < 0) {
        return COMMON_INVALID_PARAMS;
    }

    if(send(sock, msg, mlen, 0) == -1){
        printf("SendMsg fail\n");
        return COMMON_ERROR;
    }
    printf("send : %d\n", mlen);
	for(int i = 0; i<mlen; i++){
		printf("0x%02x ",*((unsigned char*)msg+i));
	}
	printf("\n");
    return COMMON_SUCCESS;
}

unsigned char Message::CalculateBCC(unsigned char* buff, int len){
    if (buff == NULL) {
        return 0x00;
    }

    unsigned char bcc= *buff;
    for(int i=1; i<len; i++){
        bcc^=*(buff+i);
    }
    return bcc;
}

int Message::SendErrorOrSuccCode(int sock, unsigned char cmd, unsigned char code){
    int ret = COMMON_ERROR;
    unsigned char* msg = NULL;
    size_t mlen = 0;
    unsigned char* length = NULL;
    msg = (unsigned char* )malloc(10);
    if (!msg) {
        printf("SendErrorCode: malloc msg fail\n");
        goto err; 
    }
    memset(msg+mlen, 0xff, 2);
    mlen+=2;
    length = CertOp::IntToUnsignedChar(2);
    if (!length) {
        printf("SendErrorCode: IntToUnsignedChar fail\n");
        return COMMON_ERROR;
    }
    memcpy(msg+mlen, length, 4);
    mlen+=4;
    memset(msg+mlen, cmd, 1);
    mlen+=1;
    memset(msg+mlen, code, 1);
    mlen+=1;
    memset(msg+mlen, Message::CalculateBCC(msg+2, 6), 1);
    mlen+=1;
    memset(msg+mlen, 0xff, 1);
    mlen+=1;
    if(Message::SendMsg(sock, (void* )msg, mlen) != COMMON_SUCCESS){
        printf("SendErrorCode: SendMsg fail\n");
        goto err; 
    }

    ret = COMMON_SUCCESS;
    err:{
        if(msg){
            free(msg);
        }
        if(length){
            free(length);
        }
    }
    return ret;
}


/**
* @}
**/

