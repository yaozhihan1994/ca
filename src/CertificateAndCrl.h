/***********************************************
* @addtogroup Nebula
* @{
* @file  : CertificateAndCrl.h
* @brief :
* @date  : 2019-04-25
***********************************************/

//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------


#ifndef CERTIFICATE_AND_CRL_H_
#define CERTIFICATE_AND_CRL_H_

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

int cb(const void *buffer, size_t size, void *key);

int CertificateToFile(const char* filename, Certificate_t *crt);

int CertificateToBuffer(unsigned char** buffer, size_t* blen, Certificate_t *crt);

Certificate_t* BufferToCertificate(unsigned char* buffer, size_t blen);

Certificate_t* FileToCertificate(const char* filename);

Crl* BufferToCrl(unsigned char* buffer, size_t blen);

Crl* FileToCrl(const char* filename);

int CrlToBuffer(unsigned char** buffer, size_t* blen, Crl *crl);

int ToBeSignedCrlToBuffer(unsigned char** buffer, size_t* blen, ToBeSignedCrl_t *tbs);

int CrlToFile(const char* filename, Crl *crl);

#endif

/**
* @}
**/



