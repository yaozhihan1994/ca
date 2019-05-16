
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

    static Crl_t* CreateCRL(EC_KEY* key, unsigned char* subrootca_hashid8, unsigned char* cca_hashid8, 
                         unsigned char* hashid10, unsigned long crt_start_difftime);

    static int CrlSign(EC_KEY* key, Crl_t* crt);
    static int CrlVerify(EC_KEY* key, Crl_t* crt);

    static void crl_manage();
    static int init_crl_list();

    static int set_crl_list(string name);
    static int send_crls(int sock, unsigned char cmd);


private:
    static list<string> crl_list_;
    static std::mutex crl_mutex_;
    static unsigned long crl_serial_number_;
};
}

#endif
/**
* @}
**/
