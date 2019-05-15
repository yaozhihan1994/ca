/***********************************************
* @addtogroup Nebula
* @{
* @file  : CertificateAndCrl.cpp
* @brief :
* @date  : 2019-04-25
***********************************************/
 
//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------
  
#include "CertificateAndCrl.h"

using namespace std;

int cb(const void *buffer, size_t size, void *key) {
//  printf("size = %d\n", size);
//  for (int i= 0; i < size; i++) {
//      printf("0x%02x ",*((unsigned char* )buffer+i));
//  }
//  printf("\n");
//  return size;
    return 0;
}

int CertificateToFile(const char* filename, Certificate_t *crt){
    if (!filename || !crt) {
        return COMMON_NULL_POINT;
    }

    FILE* fp = fopen(filename, "w+");
    if (!fp) {
        printf("Cannot open file: %s\n", filename);
        return COMMON_ERROR;
    }

    unsigned char* buffer = NULL;
    size_t blen = 0;
    if (COMMON_SUCCESS != CertificateToBuffer(&buffer, &blen, crt)) {
        printf("CertificateToFile: CertificateToBuffer fail\n");
        fclose(fp);
        return COMMON_ERROR;
    }

    for (int i = 0; i<blen; i++) {
        fprintf(fp ,"%c", *(buffer+i));
//      printf("0x%02x ", *(buffer+i));
    }
//  printf("\n%d ", blen);

    if (buffer) {
        free(buffer);
    }
    fclose(fp);
    return COMMON_SUCCESS;
}


Certificate_t* FileToCertificate(const char* filename){
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

//  cout<<"\nFileToCertificate: "<<endl;
//  for (int i = 0; i< blen; i++) {
//      printf("0x%02x ",*(buffer+i));
//  }
//  printf("\n%d\n\n", blen);

    Certificate_t* crt = 0;
//  asn_dec_rval_t dr = ber_decode(0, &asn_DEF_Certificate, (void **)(&crt), (void *)buffer, blen);
    asn_dec_rval_t dr = uper_decode_complete(0, &asn_DEF_Certificate, (void **)(&crt), (void *)buffer, blen);
    if(dr.code != RC_OK){
        printf("FileToCertificate: uper_decode_complete fail\n");
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    
    return crt;

}

int CertificateToBuffer(unsigned char** buffer, size_t* blen, Certificate_t *crt){
    *buffer = NULL;
    *blen = 0;
    if (!crt) {
        return COMMON_NULL_POINT;
    }
    asn_enc_rval_t er = uper_encode(&asn_DEF_Certificate, crt, cb, NULL);
//  asn_enc_rval_t er = der_encode(&asn_DEF_Certificate, crt, 0, NULL);
    if(er.encoded == -1) {
        fprintf(stderr, "CertificateToBuffer: uper_encode Cannot encode %s\n", er.failed_type->name);
        return COMMON_ERROR;
    } else {
        int len = ((er.encoded +7)/8);
        unsigned char* buff = (unsigned char*)MALLOC(len);
        if (!buff) {
            printf("CertificateToBuffer: malloc buff fail\n");
            return COMMON_ERROR;
        }
        asn_enc_rval_t ec = uper_encode_to_buffer(&asn_DEF_Certificate, (void *)crt, (void*)buff, len);
//      asn_enc_rval_t ec = der_encode_to_buffer(&asn_DEF_Certificate, (void *)crt, (void*)buff, er.encoded);
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

Certificate_t* BufferToCertificate(unsigned char* buffer, size_t blen){
    if (!buffer) {
        return NULL;
    }

    Certificate_t* crt = 0;
//  asn_dec_rval_t dr = ber_decode(0, &asn_DEF_Certificate, (void **)(&crt), (void *)buffer, blen);
    asn_dec_rval_t dr = uper_decode_complete(0, &asn_DEF_Certificate, (void **)(&crt), (void *)buffer, blen);

    if(dr.code != RC_OK){
        printf("BufferToCertificate: uper_decode fail\n");
        return NULL;
    }
    return crt;
}

int CrlToFile(const char* filename, Crl *crl){
    if (!filename || !crl) {
        return COMMON_NULL_POINT;
    }

    FILE* fp = fopen(filename, "w+");
    if (!fp) {
        printf("Cannot open file: %s\n", filename);
        return COMMON_ERROR;
    }

    unsigned char* buffer = NULL;
    size_t blen = 0;
    if (COMMON_SUCCESS != CrlToBuffer(&buffer, &blen, crl)) {
        printf("CrlToFile: CrlToBuffer fail\n");
        fclose(fp);
        return COMMON_ERROR;
    }

    for (int i = 0; i< blen; i++) {
        fprintf(fp ,"%c", *(buffer + i));
//      printf("0x%02x ", *(buffer+i));
    } 
//  printf("\n%d", blen);

    free(buffer);
    fclose(fp);
    return COMMON_SUCCESS;
}


Crl* FileToCrl(const char* filename){
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

//  cout<<"\nFileToCrl: "<<endl;
//  for (int i = 0; i< blen; i++) {
//      printf("0x%02x ",*(buffer+i));
//  }
//  printf("\n%d\n\n", blen);

    Crl *crl = 0;
    asn_dec_rval_t dr = uper_decode_complete(0, &asn_DEF_Crl, (void **)(&crl), (void *)buffer, blen);
//  asn_dec_rval_t dr = ber_decode(0, &asn_DEF_Crl, (void **)(&crl), (void *)buffer, blen);
    
    if(dr.code != RC_OK){
        printf("FileToCrl: uper_decode_complete fail\n");
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    return crl;
}

int CrlToBuffer(unsigned char** buffer, size_t* blen, Crl *crl){
    *buffer = NULL;
    *blen = 0;
    if (!crl) {
        return COMMON_NULL_POINT;
    }

//  xer_fprint(stdout, &asn_DEF_Crl, crl);
//  asn_enc_rval_t er = der_encode(&asn_DEF_Crl, crl, 0, NULL);
    asn_enc_rval_t er = uper_encode(&asn_DEF_Crl, crl, cb, NULL);
    if(er.encoded == -1) {
        fprintf(stderr, "CrlToBuffer: der_encode Cannot encode %s\n", er.failed_type->name);
        return COMMON_ERROR;
    } 
    else {
        int len = ((er.encoded+7)/8);
        unsigned char* buff = (unsigned char*)MALLOC(er.encoded);
        if (!buff) {
            printf("CrlToBuffer: malloc buff fail\n");
            return COMMON_ERROR;
        }
//      unsigned char buff[er.encoded];
        asn_enc_rval_t ec = uper_encode_to_buffer(&asn_DEF_Crl, (void *)crl, (void*)buff, len);
//      asn_enc_rval_t ec = der_encode_to_buffer(&asn_DEF_Crl, (void *)crl, (void*)buff, er.encoded);
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

Crl* BufferToCrl(unsigned char* buffer, size_t blen){
    if (!buffer) {
        return NULL;
    }

    Crl *crl = 0;
    asn_dec_rval_t dr = uper_decode_complete(0, &asn_DEF_Crl, (void **)(&crl), (void *)buffer, blen);
//  asn_dec_rval_t dr = ber_decode(0, &asn_DEF_Crl, (void **)(&crl), (void *)buffer, blen);
    
    if(dr.code != RC_OK){
        printf("BufferToCrl: uper_decode_complete fail\n");
        return NULL;
    }
    return crl;
}

int ToBeSignedCrlToBuffer(unsigned char** buffer, size_t* blen, ToBeSignedCrl_t *tbs){
   *buffer = NULL;
    *blen = 0;
    if (!tbs) {
        return COMMON_NULL_POINT;
    }

//  xer_fprint(stdout, &asn_DEF_Crl, crl);
//  asn_enc_rval_t er = der_encode(&asn_DEF_Crl, crl, 0, NULL);
    asn_enc_rval_t er = uper_encode(&asn_DEF_ToBeSignedCrl, tbs, cb, NULL);
    if(er.encoded == -1) {
        fprintf(stderr, "CrlToBuffer: der_encode Cannot encode %s\n", er.failed_type->name);
        return COMMON_ERROR;
    } 
    else {
        int len = ((er.encoded+7)/8);
        unsigned char* buff = (unsigned char*)MALLOC(er.encoded);
        if (!buff) {
            printf("CrlToBuffer: malloc buff fail\n");
            return COMMON_ERROR;
        }
//      unsigned char buff[er.encoded];
        asn_enc_rval_t ec = uper_encode_to_buffer(&asn_DEF_ToBeSignedCrl, (void *)tbs, (void*)buff, len);
//      asn_enc_rval_t ec = der_encode_to_buffer(&asn_DEF_Crl, (void *)crl, (void*)buff, er.encoded);
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
