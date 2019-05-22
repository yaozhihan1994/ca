
/***********************************************
* @addtogroup Nebula
* @{
* @file  : CRLMng.h
* @brief :
* @date  : 2019-05-13
***********************************************/
 
//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------

#ifndef CRL_MNG_H_
#define CRL_MNG_H_

#include <stdio.h>
#include <iostream>
#include <map>
#include <array>
#include <thread>
#include <mutex>
#include <dirent.h>

#include "asn/Crl.h"
#include "CertOp.h"

#define CRL_FILENAME "crls/"
#define CRL_SERIAL_NUMBER "serial_number/crl_serial_number"
#define CRL_VERSION 1
#define CRL_MAX_LENGTH 111

class CRLMng{
public:
    CRLMng();
    ~CRLMng();

    static int CrlToFile(const char* filename, Crl_t *crl);
    static Crl_t* FileToCrl(const char* filename);

    static int CrlToBuffer(unsigned char** buffer, size_t* blen, Crl_t *crl);
    static Crl_t* BufferToCrl(unsigned char* buffer, size_t blen);
    static int ToBeSignedCrlToBuffer(unsigned char** buffer, size_t* blen, ToBeSignedCrl_t *tbs);

    static Crl_t* CreateCRL(bool is_first, unsigned char* hashid10, unsigned long crl_start_difftime);

    static int CrlSign(EC_KEY* key, Crl_t* crl);
    static int CrlVerify(EC_KEY* key, Crl_t* crl);


    static int Init();
    static void Start();
    static void set_crl_map(std::string name, unsigned char* hashid10);
    static int get_crls(unsigned char** buffer, size_t* beln, size_t* crl_num);
    static int check_reported_crl(unsigned char* hashid10);

private:
    static void crl_manage();
    static std::thread crl_manage_thread_;
    static unsigned long get_crl_serial_number();
    static int set_crl_serial_number(unsigned long sn); 
    static int init_crl_map();

    static std::map<std::string, std::array<unsigned char, 10>> crl_map_;
    static std::mutex crl_mutex_;
    static std::mutex crl_serial_mutex_;
    static unsigned long crl_serial_number_;
};


#endif
/**
* @}
**/
