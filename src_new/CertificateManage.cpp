/***********************************************
* @addtogroup Nebula
* @{
* @file  : CertificateManage.cpp
* @brief :
* @date  : 2019-05-13
***********************************************/
 
//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------

#include <iostream>
#include <list>
#include <fstream>

#include "asn/Certificate.h"
#include "Certificate.h"
#include "Common.h"
 
using namespace CERTIFICATE;

CertificateManage::CertificateManage(){
}

CertificateManage::~CertificateManage(){
}

int CertificateManage::CertificateToFile(const char* filename, Certificate_t *crt){
    if (!filename || !crt) {
        return COMMON_NULL_POINT;
    }

    int ret = COMMON_ERROR;
    unsigned char* buffer = NULL;
    size_t blen = 0;

    if (COMMON_SUCCESS != CertificateManage::CertificateToBuffer(&buffer, &blen, crt)) {
        printf("CertificateToFile: CertificateToBuffer fail\n");
        goto err;
    }

    if(Common::BufferToFile(filename, buffer, blen) != COMMON_SUCCESS){
        printf("CertificateToFile: BufferToFile fail\n");
        goto err;
    }

    ret = COMMON_SUCCESS;
    err:{
        if (buffer) {
            free(buffer);
        }
    }
    return ret;
}

Certificate_t* CertificateManage::FileToCertificate(const char* filename){
    if (!filename) {
        return NULL;
    }

    FILE* fp = fopen(filename, "r");
    if (!fp) {
        printf("Cannot open file: %s\n", filename);
        return NULL;
    }

    unsigned char buffer[1024] = {};
    size_t blen = 0;
    for (int i = 0; true; i++, blen++) {
        if (1 != fread(buffer + i, sizeof(unsigned char), 1, fp)) break;
    }

    Certificate_t* crt = 0;
    asn_dec_rval_t dr = uper_decode_complete(0, &asn_DEF_Certificate, (void **)(&crt), (void *)buffer, blen);
    if(dr.code != RC_OK){
        printf("FileToCertificate: uper_decode_complete fail\n");
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    
    return crt;
}

int CertificateManage::CertificateToBuffer(unsigned char** buffer, size_t* blen, Certificate_t *crt){
    if (!crt) {
        return COMMON_NULL_POINT;
    }
    asn_enc_rval_t er = uper_encode(&asn_DEF_Certificate, crt, Common::uper_callback, NULL);
    if(er.encoded == -1) {
        fprintf(stderr, "CertificateToBuffer: uper_encode Cannot encode %s\n", er.failed_type->name);
        return COMMON_ERROR;
    } else {
        int len = ((er.encoded +7)/8);
        unsigned char* buff = (unsigned char*)malloc(len);
        if (!buff) {
            printf("CertificateToBuffer: malloc buff fail\n");
            return COMMON_ERROR;
        }
        asn_enc_rval_t ec = uper_encode_to_buffer(&asn_DEF_Certificate, (void *)crt, (void*)buff, len);
        if(ec.encoded == -1) {
            fprintf(stderr, "CertificateToBuffer: der_encode_to_buffer Cannot encode %s\n", ec.failed_type->name);
            if (buff) {
                free(buff);
            }
            return COMMON_ERROR;
        } else {
        *blen = ((ec.encoded + 7) / 8);
        *buffer = buff;
        }
        return COMMON_SUCCESS;
    }
}

Certificate_t* CertificateManage::BufferToCertificate(unsigned char* buffer, size_t blen){
    if (!buffer) {
        return NULL;
    }

    Certificate_t* crt = 0;
    asn_dec_rval_t dr = uper_decode_complete(0, &asn_DEF_Certificate, (void **)(&crt), (void *)buffer, blen);

    if(dr.code != RC_OK){
        printf("BufferToCertificate: uper_decode fail\n");
        return NULL;
    }
    return crt;
}

int CertificateManage::CertificateSign(EC_KEY* key, Certificate_t* crt){

    if (!key || !crt) {
        return COMMON_NULL_POINT;
    }

    int ret = COMMON_ERROR;
    unsigned char* sig = NULL;
    size_t slen = 0;
    unsigned char *msg = NULL;
    int mlen = 0;

    if(CertificateManage::CertificateToBuffer(&msg, &mlen, crt) != COMMON_SUCCESS){
        printf("CertificateSign: CertificateToBuffer fail\n");
        goto err;
    }

    if(Common::SignData(key, crt->subjectInfo.subjectName.buf, msg, mlen, &sig, &slen) != COMMON_SUCCESS){
        printf("CertificateSign: SignData fail\n");
        goto err;
    }
    memcpy(crt->signature.choice.signature.buf, sig, SIGNATURE_LENGTH);

    ret = COMMON_SUCCESS;
    err:{
        if (msg) {
            free(msg);
        }
        if (sig) {
            free(sig);
        }
    }
    return ret;
}
int CertificateManage::CertificateVerify(EC_KEY* key, Certificate_t* crt){
    
    if (!key || !crt) {
        return ret;
    }

    int ret = COMMON_ERROR;
    unsigned char* msg = NULL;
    size_t mlen = 0;

    unsigned char* sig = (unsigned char*)calloc(crt->signature.choice.signature.size, sizeof(unsigned char));
    if (!sig) {
        printf("CertificateVerify: calloc sig fail\n");
        goto err;
    }
    memcpy(sig, crt->signature.choice.signature.buf, crt->signature.choice.signature.size);
    memset(crt->signature.choice.signature.buf, 0, 32);

    if(CertificateManage::CertificateToBuffer(&msg, &mlen, crt) != COMMON_SUCCESS){
        printf("CertificateVerify: CertificateToBuffer fail\n");
        goto err;
    }

    if (Common::VerifySignedData(key, sig, crt->signature.choice.signature.size, crt->subjectInfo.subjectName.buf, msg, mlen) != COMMON_SUCCESS) {
        printf("CertificateVerify: VerifySignedData fail\n");
        goto err;
    }

    memcpy(crt->signature.choice.signature.buf, sig, 32);
    ret = COMMON_SUCCESS;
    err:{
        if (sig) {
            free(sig);
        }
        if (msg) {
            free(msg);
        }
    }
    return ret;
}

Certificate_t* CertificateManage::CreateCertificate(e_CertificateType ctype, e_SubjectType  stype, unsigned char* public_key, unsigned char* sign_crt_hashid8, EC_KEY* sign_key){
    int ret = COMMON_ERROR;
    Certificate_t* crt = 0;
    unsigned char* subject_name = SUBJECT_INFO_NAME;
    size_t subject_name_len = strlen(subject_name);
    unsigned char* buffer = NULL;
    size_t blen = 0;
    unsigned char* sig = NULL;
    size_t slen = 0;

    crt = (Certificate_t* )calloc(1, sizeof(Certificate_t));
    if (!crt) {
        printf("CreateCertificate calloc crt fail\n");
        goto err;
    }

    crt->signature.present = Signature_PR_signature;
    crt->signature.choice.signature.buf =  (uint8_t* )malloc(SIGNATURE_LENGTH);
    memset(crt->signature.choice.signature.buf, 0, SIGNATURE_LENGTH);
    crt->signature.choice.signature.size = SIGNATURE_LENGTH;

    crt->signerInfo = (SignerInfo_t*)calloc(1, sizeof(SignerInfo_t));
    if (type == e_CertificateType.ROOT_CA) {
        crt->signerInfo->present = SignerInfo_PR_self;
        crt->signerInfo->choice.self = 0;
    }else{
        crt->signerInfo->present = SignerInfo_PR_certificateDigestWithSM3;
        crt->signerInfo->choice.certificateDigestWithSM3.buf = (uint8_t* )malloc(CERTIFICATE_DGST_WITH_SM3_LENGTH);
        memcpy(crt->signerInfo->choice.certificateDigestWithSM3.buf, sign_crt_hashid8, CERTIFICATE_DGST_WITH_SM3_LENGTH);
        crt->signerInfo->choice.certificateDigestWithSM3.size = CERTIFICATE_DGST_WITH_SM3_LENGTH;
    }

    crt->subjectAttributes.verificationKey = (PublicKey_t*)calloc(1, sizeof(PublicKey_t));
    crt->subjectAttributes.verificationKey->present = PublicKey_PR_signKey;
    crt->subjectAttributes.verificationKey->choice.signKey.buf =  (uint8_t* )malloc(PUBLIC_KEY_LENGTH);
    memset(crt->subjectAttributes.verificationKey->choice.signKey.buf, 0, PUBLIC_KEY_LENGTH);
    memcpy(crt->subjectAttributes.verificationKey->choice.signKey.buf, public_key, PUBLIC_KEY_LENGTH);
    crt->subjectAttributes.verificationKey->choice.signKey.size = PUBLIC_KEY_LENGTH;

    crt->subjectInfo.subjectName.buf = (uint8_t* )malloc(subject_name_len);
    memset(crt->subjectInfo.subjectName.buf, 0, subject_name_len);
    memcpy(crt->subjectInfo.subjectName.buf, subject_name, subject_name_len);
    crt->subjectInfo.subjectName.size = snlen;

    crt->subjectInfo.subjectType = stype;

    crt->validityRestrictions.present = ValidityRestriction_PR_timeStartAndEnd;
    crt->validityRestrictions.choice.timeStartAndEnd.startValidity = Common::get_difftime_by_now();
    crt->validityRestrictions.choice.timeStartAndEnd.endValidity = Common::get_difftime_by_years(CA_CRT_VALIDITY_PERIOD_YEARS);

    crt->version = CERTIFICATE_VERSION;

    if(COMMON_SUCCESS != CertificateManage::CertificateToBuffer(&buffer, &blen, crt)){
        printf("CreateCertificate CertificateToBuffer fail\n");
        goto err;
    }

    if(COMMON_SUCCESS != Common::SignData(key, crt->subjectInfo.subjectName.buf, buffer, blen, &sig, &slen)){
        printf("CreateCertificate SignData fail\n");
        goto err;
    }

    memcpy(crt->signature.choice.signature.buf, sig, CRT_SIGNATURE_LENGTH);
    ret = COMMON_SUCCESS;
    err:{
        if (sig) {
            free(sig);
        }
    }
    return ret;
}

void CertificateManage::pcrt_manage(){

}

void CertificateManage::rcrt_manage(){

}

void CertificateManage::get_pcrt(){

}

void CertificateManage::get_rcrt(){

}

void CertificateManage::init_pcrt_list(){

}

void CertificateManage::init_rcrt_list(){

}

/**
* @}
**/
