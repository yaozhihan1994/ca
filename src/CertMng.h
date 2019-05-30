/***********************************************
* @addtogroup Nebula
* @{
* @file  : CertMng.h
* @brief :
* @date  : 2019-05-13
***********************************************/

//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------

#ifndef CERT_MNG_H_
#define CERT_MNG_H_

#include <stdio.h>
#include <iostream>
#include <list>
#include <thread>
#include <mutex>
#include <dirent.h>

#include "CertOp.h"

#define PCRTS "pcrts/"
#define RCRTS "rcrts/"

#define DEFAULT_DEVICE_SERIAL_NUMBER "00000001"
#define SUBJECT_INFO_NAME "xingyunhulian"
#define PCRT_POOL 5
#define RCRT_POOL 5
#define CERTIFICATE_VERSION 2
#define CERT_LENGTH 162

class CertMng{
public:
    CertMng();
    ~CertMng();

    static int CertificateToFile(const char* filename, Certificate_t *crt);
    static Certificate_t* FileToCertificate(const char* filename);

    static int CertificateToDer(unsigned char** buffer, size_t* blen, Certificate_t* crt);
    static Certificate_t* DerToCertificate(unsigned char* buffer, size_t blen);

    static int CertificateToBuffer(unsigned char** buffer, size_t* blen, Certificate_t* crt);
    static Certificate_t* BufferToCertificate(unsigned char* buffer, size_t blen);

    //need free
    static int get_sign_der_buffer(Certificate_t* crt, unsigned char** buffer, size_t* blen);

    static int CertificateSign(EC_KEY* key, Certificate_t* crt);
    static int CertificateVerify(EC_KEY* key, Certificate_t* crt);

    static Certificate_t* CreateCertificate(int ctype, int  stype, 
                                            unsigned char* public_key, unsigned char* sign_crt_hashid8, EC_KEY* sign_key);

    static int get_pcrt_and_pkey(unsigned char** buffer, size_t* blen);
    static int get_rcrt_and_rkey(unsigned char** buffer, size_t* blen);

    static int Init();
    static void Start();

private:
    //filename "end_gmtime"_"crt_serial_number"
    static std::list<std::string> pcrt_list_;
    static std::mutex pcrt_mutex_;

    static std::list<std::string> rcrt_list_;
    static std::mutex rcrt_mutex_;

    static unsigned long pcrt_serial_number_;
    static unsigned long rcrt_serial_number_;

    static int init_pcrt_list();
    static int init_rcrt_list();

    static int create_a_pcrt();
    static int create_a_rcrt();

    static void pcrt_manage();
    static void rcrt_manage();

    static std::thread pcrt_manage_thread_;
    static std::thread rcrt_manage_thread_;
};

#endif

/**
* @}
**/
