
/***********************************************
* @addtogroup Nebula
* @{
* @file  : CrlManage.cpp
* @brief :
* @date  : 2019-05-13
***********************************************/
 
//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------




#include "CrlManage.h"

using namespace CRL;

int CrlManage::CrlToFile(const char* filename, Crl_t *crt){

    if (!filename || !crl) {
        return COMMON_NULL_POINT;
    }

    int ret = COMMON_ERROR;
    unsigned char* buffer = NULL;
    size_t blen = 0;
    if (COMMON_SUCCESS != CrlManage::CrlToBuffer(&buffer, &blen, crl)) {
        printf("CrlToFile: CrlToBuffer fail\n");
        goto err;
    }

    if (COMMON_SUCCESS != Common::BufferToFile(filename, buffer, blen)) {
        printf("CrlToFile: BufferToFile fail\n");
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

Crl_t* CrlManage::FileToCrl(const char* filename){
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

    Crl *crl = 0;
    asn_dec_rval_t dr = uper_decode_complete(0, &asn_DEF_Crl, (void **)(&crl), (void *)buffer, blen);
    if(dr.code != RC_OK){
        printf("FileToCrl: uper_decode_complete fail\n");
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    return crl;
}

int CrlManage::CrlToBuffer(unsigned char** buffer, size_t* blen, Crl_t *crt){
    if (!crl) {
        return COMMON_NULL_POINT;
    }

    asn_enc_rval_t er = uper_encode(&asn_DEF_Crl, crl, cb, NULL);
    if(er.encoded == -1) {
        fprintf(stderr, "CrlToBuffer: der_encode Cannot encode %s\n", er.failed_type->name);
        return COMMON_ERROR;
    } 
    else {
        int len = ((er.encoded+7)/8);
        unsigned char* buff = (unsigned char*)malloc(er.encoded);
        if (!buff) {
            printf("CrlToBuffer: malloc buff fail\n");
            return COMMON_ERROR;
        }
        asn_enc_rval_t ec = uper_encode_to_buffer(&asn_DEF_Crl, (void *)crl, (void*)buff, len);
        if(ec.encoded == -1) {
            fprintf(stderr, "CrlToBuffer: der_encode_to_buffer Cannot encode %s\n", ec.failed_type->name);
            if (buff) {
                free(buff);
            }
            return COMMON_ERROR;
        } else {
        *blen = ((ec.encoded+7)/8);
        *buffer = buff;
        }
        return COMMON_SUCCESS;
    }
}

Crl_t* CrlManage::BufferToCrl(unsigned char* buffer, size_t blen){
    if (!buffer) {
        return NULL;
    }

    Crl *crl = 0;
    asn_dec_rval_t dr = uper_decode_complete(0, &asn_DEF_Crl, (void **)(&crl), (void *)buffer, blen);    
    if(dr.code != RC_OK){
        printf("BufferToCrl: uper_decode_complete fail\n");
        return NULL;
    }
    return crl;
}

int CrlManage::ToBeSignedCrlToBuffer(unsigned char** buffer, size_t* blen, ToBeSignedCrl_t *tbs){

    if (!tbs) {
        return COMMON_NULL_POINT;
    }
    asn_enc_rval_t er = uper_encode(&asn_DEF_ToBeSignedCrl, tbs, cb, NULL);
    if(er.encoded == -1) {
        fprintf(stderr, "CrlToBuffer: der_encode Cannot encode %s\n", er.failed_type->name);
        return COMMON_ERROR;
    } 
    else {
        int len = ((er.encoded+7)/8);
        unsigned char* buff = (unsigned char*)malloc(er.encoded);
        if (!buff) {
            printf("CrlToBuffer: malloc buff fail\n");
            return COMMON_ERROR;
        }
        asn_enc_rval_t ec = uper_encode_to_buffer(&asn_DEF_ToBeSignedCrl, (void *)tbs, (void*)buff, len);
        if(ec.encoded == -1) {
            fprintf(stderr, "CrlToBuffer: der_encode_to_buffer Cannot encode %s\n", ec.failed_type->name);
            if (buff) {
                free(buff);
            }
            return COMMON_ERROR;
        } else {
        *blen = ((ec.encoded+7)/8);
        *buffer = buff;
        }
        return COMMON_SUCCESS;
    }
}

int CrlManage::CreateCRL(EC_KEY* key, unsigned char* subrootca_hash, unsigned char* cca_hash, unsigned char* hashid10, unsigned long crt_start_time){



}





int CrlManage::CrlSign(EC_KEY* key, Crl_t* crt){
    if (!key || !crl) {
        return COMMON_NULL_POINT;
    }

    int ret = COMMON_ERROR;
    unsigned char* buffer = NULL;
    size_t blen = 0;
    ECDSA_SIG* signature = NULL;
    unsigned char* sig = NULL;
    size_t slen = 0;

    if(ToBeSignedCrlToBuffer(&buffer, &blen, &(crl->unsignedCrl)) != COMMON_SUCCESS){
        printf("CrlSign: ToBeSignedCrlToBuffer fail\n");
        goto err;
    }

    signature = SM2_do_sign(key, EVP_sm3(), crl->signerInfo.choice.certificateDigestWithSM3.buf, buffer, blen);
    if (!signature) {
        printf("CrlSign: SM2_do_sign fail\n");
        goto err;
    }
    slen = i2d_ECDSA_SIG(signature, &sig);
    if (slen == 0) {
        printf("CrlSign: i2d_ECDSA_SIG fail\n");
        goto err;
    }                       
    memcpy(crl->signature.choice.signature.buf, sig, SIGNATURE_LENGTH);

    ret = COMMON_SUCCESS;
    err:{
        if (buffer) {
            free(buffer);
        }
        if (signature) {
            ECDSA_SIG_free(signature);
        }
    }
    return ret;
}

int CrlManage::CrlVerify(EC_KEY* key, Crl_t* crt){
    return 0;
}

void CrlManage::crl_manage(){

}


/**
* @}
**/
