
/***********************************************
* @addtogroup Nebula
* @{
* @file  : Init.h
* @brief :
* @date  : 2019-04-25
***********************************************/

//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------


#ifndef INIT_H_
#define INIT_H_

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>

#include <utility>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <iostream>
#include <ctime>

#include "asn/Certificate.h"
#include "asn/Crl.h"
#include "CommonError.h"
#include "Common.h"
#include "CertificateAndCrl.h"

#define ROOTCACRT "crts/rootCA"
#define ROOTCAKEY "keys/rootCA"
#define SUBROOTCACRT "crts/SubrootCA"
#define SUBROOTCAKEY "keys/SubrootCA"
#define ECACRT "crts/ECA"
#define ECAKEY "keys/ECA"
#define PCACRT "crts/PCA"
#define PCAKEY "keys/PCA"
#define RCACRT "crts/RCA"
#define RCAKEY "keys/RCA"
#define CCACRT "crts/CCA"
#define CCAKEY "keys/CCA"

#define PCA_CRTS "pca_crts/"
#define RCA_CRTS "rca_crts/"
#define PCA_KEYS "pca_keys/"
#define RCA_KEYS "rca_keys/"

#define CRL_FILENAME "crls/"

#define SUBJECT_INFO_NAME "xingyunhulian"
#define PCA_POOL 1
#define RCA_POOL 1
#define CRL_SERIAL_NUMBER "crl_serial_number"
#define DEVICE_SERIAL_NUMBER "device_serial_number"

int Init();

int CheckCA();

int CreateRootCA();

int CreateSubCA(Certificate_t* rootca, EC_KEY* rootkey, e_SubjectType  type, const unsigned char* filename_crt, const unsigned char* filename_key);

int CreateCRT(Certificate_t* rootca, EC_KEY* rootkey, e_SubjectType type,
              const unsigned char* filename_crt, const unsigned char* filename_key,
              unsigned long* end_time, unsigned char** pri_key);

int LoadCaAndKeyFromFile(const char* filename_crt, const char* filename_key, Certificate_t** crt, EC_KEY** key, 
                         unsigned char** crt_buff, size_t* crt_buff_len);

int GetCaAndKeyFromFile(const char* filename_crt, const char* filename_key, Certificate_t** crt, EC_KEY** key);

int CreateNewECA(Certificate_t* rootca, EC_KEY* rootkey, e_SubjectType  type, unsigned char* key_crt, size_t* clen);
#endif

/**
* @}
**/



