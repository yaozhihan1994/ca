
/***********************************************
* @addtogroup Nebula
* @{
* @file  : CrlManage.h
* @brief :
* @date  : 2019-05-13
***********************************************/
 
//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------

#ifndef CRL_MANAGE_H_
#define CRL_MANAGE_H_

#include "Common.h"

namespace CRL{


#define CRL_FILENAME "crls/"
#define CRL_SERIAL_NUMBER "crl_serial_number"
#define CRL_VERSION 1


class CrlManage{
public:
    CrlManage();
    ~CrlManage();

    static int CrlToFile(const char* filename, Crl_t *crt);
    static Crl_t* FileToCrl(const char* filename);

    static int CrlToBuffer(unsigned char** buffer, size_t* blen, Crl_t *crt);
    static Crl_t* BufferToCrl(unsigned char* buffer, size_t blen);
    static int ToBeSignedCrlToBuffer(unsigned char** buffer, size_t* blen, ToBeSignedCrl_t *tbs);

    static int CreateCRL(EC_KEY* key, unsigned char* subrootca_hash, unsigned char* cca_hash, unsigned char* hashid10, unsigned long crt_start_time);

    static int CrlSign(EC_KEY* key, Crl_t* crt);
    static int CrlVerify(EC_KEY* key, Crl_t* crt);


    static void crl_manage();
    static int init_crl_list();

private:
    static list crl_list_;
    static pthread_mutex_t crl_mutex_;

};
}

#endif
/**
* @}
**/
