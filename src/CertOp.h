﻿/***********************************************
* @addtogroup Nebula
* @{
* @file  : CertOp.h
* @brief :
* @date  : 2019-05-13
***********************************************/

//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------

#ifndef CERT_OP_H_
#define CERT_OP_H_

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctime>
#include <unistd.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/sm2.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>

#include "asn/Certificate.h"

#define CA_CRT_VALIDITY_PERIOD_YEARS 10 
#define DEVICE_CRT_VALIDITY_PERIOD_DAYS 7
#define SIGNATURE_LENGTH 64
#define PUBLIC_KEY_LENGTH 64
#define PRIVATE_KEY_LENGTH 32
#define SM3_HASH_LENGTH 32
#define CERTIFICATE_DGST_WITH_SM3_LENGTH 8
#define UNSIGNED_CRL_HASHID_LENGTH 10
#define DEVICE_ID_LENGTH 8

#define COMMON_SUCCESS 0
#define	COMMON_ERROR -1
#define	COMMON_INVALID_PARAMS -2
#define	COMMON_NULL_POINT -3

#define ROOT_CA_CRT 0
#define SUBROOT_CA_CRT 1
#define E_CA_CRT 2
#define P_CA_CRT 3
#define R_CA_CRT 4
#define C_CA_CRT 5
#define P_CRT 6
#define R_CRT 7
#define E_CRT 8

#define SM2_USER_ID "1234567812345678"
#define DEFAULT_DEVICE_SERIAL_NUMBER "00000001"
#define SUBJECT_INFO_NAME "xingyunhulian"

typedef struct CaInfo{
    EC_KEY* key;
    Certificate_t* crt;
    unsigned char* buffer;
    size_t blen;
    unsigned char* hashid8;

} s_CaInfo;

extern s_CaInfo g_rootca;
extern s_CaInfo g_subrootca;
extern s_CaInfo g_eca;
extern s_CaInfo g_pca;
extern s_CaInfo g_rca;
extern s_CaInfo g_cca;
extern std::string g_exe_file_path;

extern std::string g_serial_number_file_path;
extern std::string g_device_sn_file_path;
extern std::string g_crl_sn_file_path;

extern std::string g_crl_file_path;

extern std::string g_ca_file_path;
extern std::string g_rootca_crt_file_path;
extern std::string g_rootca_key_file_path;
extern std::string g_subrootca_crt_file_path;
extern std::string g_subrootca_key_file_path;
extern std::string g_eca_crt_file_path;
extern std::string g_eca_key_file_path;
extern std::string g_pca_crt_file_path;
extern std::string g_pca_key_file_path;
extern std::string g_rca_crt_file_path;
extern std::string g_rca_key_file_path;
extern std::string g_cca_crt_file_path;
extern std::string g_cca_key_file_path;

extern std::string g_pcrts_file_path;
extern std::string g_rcrts_file_path;

class CertOp{
public:
    CertOp();
    ~CertOp();

    static int uper_callback(const void *buffer, size_t size, void *key);

    static EC_KEY* CreateSm2KeyPair();

    static int SignData(EC_KEY* key, const unsigned char* msg, size_t msg_len, unsigned char** sig, size_t* sig_len);

    static int VerifySignedData(EC_KEY* key, const unsigned char* sig, size_t sig_len, const unsigned char* msg, int msg_len);

    static int EncryptData(EC_KEY* key, const unsigned char* msg, size_t msg_len, unsigned char** ciphertext, size_t* ciphertext_len);

    static int DecryptData(EC_KEY* key, const unsigned char* ciphertext, size_t ciphertext_len, unsigned char** plaintext, size_t* plaintext_len);

    //need free
    static int Sm3Hash(unsigned char* msg, size_t msg_len, unsigned char** hash, size_t* hash_len);

    static int EncryptDataBySm4(SymmetricAlgorithm type, unsigned char *plaintext, int plaintext_len, unsigned char *key,
                                                           unsigned char *iv, unsigned char **ciphertext, int* ciphertext_len);
    static int DecryptDataBySm4(SymmetricAlgorithm type, unsigned char *ciphertext, int ciphertext_len, unsigned char* key, 
                                                           unsigned char* iv, unsigned char** plaintext, int* plaintext_len);
    static int DeriveKey(EC_KEY* mkey, EC_KEY* okey, unsigned char** key, size_t* keylen);

    //need free
    static unsigned char* get_sm2_public_key(const EC_KEY* key);
    static unsigned char* get_sm2_private_key(const EC_KEY* key);

    static unsigned long get_difftime_by_now();
    static unsigned long get_difftime_2004();
    static unsigned long get_difftime_by_days(int days);

    static unsigned long get_difftime_by_years(int years);

    static unsigned long get_time_now();

    static int get_hour_now();

    static unsigned long get_time_by_diff(unsigned long diff);

    //need free
    static int FileToBuffer(const char* filename, unsigned char** buff, size_t* blen);

    static int BufferToFile(const char* filename, unsigned char* buff, size_t blen);

    static int KeyToFile(const char* filename, EC_KEY* key);

    static EC_KEY* FileToKey(const char* filename);

    static bool VerifyDeviceSerialNumber(char* serial_number, size_t slen);

    static std::string UnsignedLongToString(unsigned long t);

    static unsigned int UnsignedCharToInt(unsigned char* num);

    static unsigned char* IntToUnsignedChar(unsigned int num);

    static void print_buffer(unsigned char* buffer, size_t blen);

};

#endif

/**
* @}
**/

