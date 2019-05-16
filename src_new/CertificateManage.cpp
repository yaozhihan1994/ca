﻿/***********************************************
* @addtogroup Nebula
* @{
* @file  : CertificateManage.cpp
* @brief :
* @date  : 2019-05-13
***********************************************/
 
//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------


#include "CertificateManage.h"
 
using namespace CERTIFICATE;

std::list<string> CertificateManage::pcrt_list_;
std::mutex CertificateManage::pcrt_mutex_;

std::list<string> CertificateManage::rcrt_list_;
std::mutex CertificateManage::rcrt_mutex_;

unsigned long CertificateManage::pcrt_serial_number_ = 0;
unsigned long CertificateManage::rcrt_serial_number_ = 0;

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

    Certificate_t* crt = NULL;
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

Certificate_t* CertificateManage::CreateCertificate(e_CertificateType ctype, e_SubjectType  stype, 
                                                                                       unsigned char* public_key, unsigned char* sign_crt_hashid8, EC_KEY* sign_key){
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

    while (true) {
        if (pcrt_list_.size() < PCRT_POOL) {
            if(CertificateManage::create_a_pcrt() != COMMON_SUCCESS){
                printf("pcrt_manage: create_a_pcrt fail\n");
                break;
            }
        }

        if (Common::get_hour_now() == 2) {
            pcrt_mutex_.lock();
            for (std::list<string>::iterator i = pcrt_list_.begin(); i != pcrt_list_.end(); ){
                string name(*i);
                if (strtoul(name.substr(0, name.find("_"))) < Common::get_time_now()){
                    pcrt_list_.erase(i++);
                    name = PCRTS + name;
                    remove(name.c_str());
                }
                usleep(1);
            }
            pcrt_mutex_.unlock();
        }
        usleep(1);
    }
    printf("pcrt_manage thread dead\n");
}

void CertificateManage::rcrt_manage(){

    while (true) {
        if (rcrt_list_.size() < RCRT_POOL) {
            if(CertificateManage::create_a_rcrt() != COMMON_SUCCESS){
                printf("rcrt_manage: create_a_rcrt fail\n");
                break;
            }
        }

        if (Common::get_hour_now() == 2) {
            rcrt_mutex_.lock();
            for (std::list<string>::iterator i = rcrt_list_.begin(); i != rcrt_list_.end(); ){
                string name(*i);
                if (strtoul(name.substr(0, name.find("_"))) < Common::get_time_now()){
                    rcrt_list_.erase(i++);
                    name = RCRTS + name;
                    remove(name.c_str());
                }
                usleep(1);
            }
            rcrt_mutex_.unlock();
        }
        usleep(1);
    }
    printf("rcrt_manage thread dead\n");
}

int CertificateManage::get_pcrt_and_pkey(unsigned char** crt, size_t* clen, unsigned char** key, size_t* klen){
    std::lock_guard<std::mutex> lck(pcrt_mutex_);
    int ret = COMMON_ERROR;
    unsigned char* buffer = NULL;
    size_t blen = 0;
    unsigned char* pcrt = NULL;
    size_t pcrt_len = 0;
    unsigned char* pkey = NULL;
    size_t pkey_len = 0;

    for (std::list<string>::iterator i = pcrt_list_.begin(); i != pcrt_list_.end(); ) {
        string name = *i;
        //end_time > now ? 
        if ( strtoul(name.substr(0, name.find("_"))) > Common::get_time_now() ) {
            if(Common::FileToBuffer(name.c_str(), &buffer, &blen) != COMMON_SUCCESS){
                printf("CertificateManage: get_pcrt_and_pkey FileToBuffer fail\n");
                goto err;
            }   
            pkey = (unsigned char* )malloc(PRIVATE_KEY_LENGTH);
            if (!pkey) {
                printf("CertificateManage: get_pcrt_and_pkey malloc pkey fail\n");
                goto err;
            }

            pcrt = (unsigned char* )malloc(blen - PRIVATE_KEY_LENGTH);
            if (!pcrt) {
                printf("CertificateManage: get_pcrt_and_pkey malloc pcrt fail\n");
                free(pkey);
                goto err;
            }
            memcpy(pkey, buffer, PRIVATE_KEY_LENGTH);
            memcpy(pcrt, buffer + PRIVATE_KEY_LENGTH, blen - PRIVATE_KEY_LENGTH);
            pkey_len = PRIVATE_KEY_LENGTH;
            pcrt_len = blen - PRIVATE_KEY_LENGTH;

            pcrt_list_.erase(i++);
            name = PCRTS + name;
            remove(name.c_str());
            break;
        }else{
            i++;
        }
    }
    if (!pcrt || !pkey) {
        printf("CertificateManage: get_pcrt_and_pkey no pcrt can use\n");
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

int CertificateManage::get_rcrt_and_rkey(unsigned char** crt, size_t* clen, unsigned char** key, size_t* klen){
    std::lock_guard<std::mutex> lck(rcrt_mutex_);
    int ret = COMMON_ERROR;
    unsigned char* buffer = NULL;
    size_t blen = 0;
    unsigned char* rcrt = NULL;
    size_t rcrt_len = 0;
    unsigned char* rkey = NULL;
    size_t rkey_len = 0;

    for (std::list<string>::iterator i = rcrt_list_.begin(); i != rcrt_list_.end(); ) {
        string name = *i;
        //end_time > now ? 
        if ( strtoul(name.substr(0, name.find("_"))) > Common::get_time_now() ) {
            if(Common::FileToBuffer(name.c_str(), &buffer, &blen) != COMMON_SUCCESS){
                printf("CertificateManage: get_rcrt_and_rkey FileToBuffer fail\n");
                goto err;
            }   
            rkey = (unsigned char* )malloc(PRIVATE_KEY_LENGTH);
            if (!rkey) {
                printf("CertificateManage: get_rcrt_and_rkey malloc rkey fail\n");
                goto err;
            }

            rcrt = (unsigned char* )malloc(blen - PRIVATE_KEY_LENGTH);
            if (!rcrt) {
                printf("CertificateManage: get_rcrt_and_rkey malloc rcrt fail\n");
                free(rkey);
                goto err;
            }
            memcpy(rkey, buffer, PRIVATE_KEY_LENGTH);
            memcpy(rcrt, buffer + PRIVATE_KEY_LENGTH, blen - PRIVATE_KEY_LENGTH);
            rkey_len = PRIVATE_KEY_LENGTH;
            rcrt_len = blen - PRIVATE_KEY_LENGTH;

            rcrt_list_.erase(i++);
            name = RCRTS + name;
            remove(name.c_str());
            break;
        }else{
            i++;
        }
    }
    if (!rcrt || !rkey) {
        printf("CertificateManage: get_rcrt_and_rkey no rcrt can use\n");
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

int CertificateManage::Init(){
    if (CertificateManage::init_pcrt_list() != COMMON_SUCCESS) {
        printf("Init: init_pcrt_list fail\n");
        return COMMON_ERROR;
    }
    if (CertificateManage::init_rcrt_list() != COMMON_SUCCESS) {
        printf("Init: init_rcrt_list fail\n");
        return COMMON_ERROR;
    }
    return COMMON_SUCCESS;
}


void CertificateManage::init_pcrt_list(){
    printf("CertificateManage init_pcrt_list start\n");
    std::lock_guard<std::mutex> lck(pcrt_mutex_);
    DIR* dir = opendir(PCRTS);
    dirent* p = NULL;
    pcrt_list_.clear();
    while((p = readdir(dir)) != NULL){
        if(p->d_name[0] != '.'){
            string name(p->d_name);
            pcrt_list_.push_back(name);
            unsigned long sn = strtoul(name.substr(name.find("_") + 1));
            pcrt_serial_number_ = sn > pcrt_serial_number_? sn : pcrt_serial_number_;
        }
    }
    closedir(dir);
    printf("CertificateManage pcrt_list_ size: %d\n",  pcrt_list_.size());
    printf("CertificateManage init_pcrt_list end\n");
}

void CertificateManage::init_rcrt_list(){
    printf("CertificateManage init_rcrt_list start\n");
    std::lock_guard<std::mutex> lck(rcrt_mutex_);
    DIR* dir = opendir(PCRTS);
    dirent* p = NULL;
    rcrt_list_.clear();
    while((p = readdir(dir)) != NULL){
        if(p->d_name[0] != '.'){
            string name(p->d_name);
            rcrt_list_.push_back(name);
            unsigned long sn = strtoul(name.substr(name.find("_") + 1));
            rcrt_serial_number_ = sn > rcrt_serial_number_? sn : rcrt_serial_number_;
        }
    }
    closedir(dir);
    printf("CertificateManage rcrt_list_ size: %d\n",  rcrt_list_.size());
    printf("CertificateManage init_rcrt_list end\n");
}

int CertificateManage::create_a_pcrt(){
    int ret = COMMON_ERROR;
    Certificate_t* pcrt = NULL;
    EC_KEY* pkey = NULL;
    unsigned char* pri_key = NULL;
    unsigned char* pub_key = NULL;
    unsigned char* crt_buffer = NULL;
    size_t crt_len = 0;
    unsigned char* buffer = NULL;
    size_t blen = 0;
    unsigned long pcrt_end_gmtime = 0;
    string crt_name(PCRTS);
    string file_name;

    if ((pkey = Common::CreateSm2KeyPair()) == NULL) {
        printf("create_a_pcrt: CreateSm2KeyPair pkey fail\n");
        goto err;
    }

    if ((pri_key = Common::get_sm2_private_key(pkey)) == NULL) {
        printf("create_a_pcrt: get_sm2_private_key fail\n");
        goto err;
    }

    if ((pub_key = Common::get_sm2_public_key(pkey)) == NULL) {
        printf("create_a_pcrt: get_sm2_public_key fail\n");
        goto err;
    }

    if((pcrt = CertificateManage::CreateCertificate(e_CertificateType.P_CRT, e_SubjectType.SubjectType_authorizationTicket,
                                                    pub_key, g_pca_hashid8, g_pca_key)) == NULL){
        printf("create_a_pcrt: CreateCertificate pcrt fail\n");
        goto err;
    }
    pcrt_serial_number++;
    pcrt_end_gmtime = Common::get_time_by_diff(pcrt->validityRestrictions.choice.timeStartAndEnd.endValidity);

    if (CertificateManage::CertificateToBuffer(&crt_buffer, &crt_len, pcrt) != COMMON_SUCCESS) {
        printf("create_a_pcrt: CertificateToBuffer fail\n");
        goto err;
    }

    buffer = (unsigned char* )malloc(crt_len + PRIVATE_KEY_LENGTH);
    if (!buffer) {
        printf("create_a_pcrt: malloc buffer fail\n");
        goto err;
    }
    blen = crt_len + PRIVATE_KEY_LENGTH;

    memcpy(buffer, pri_key, PRIVATE_KEY_LENGTH);
    memcpy(buffer+PRIVATE_KEY_LENGTH, crt_buffer, crt_len);

    file_name = Common::ToString(pcrt_end_gmtime) +"_"+ Common::ToString(pcrt_serial_number);
    crt_name+= file_name;
    if (Common::BufferToFile(crt_name.c_str(), buffer, blen) != COMMON_SUCCESS) {
        printf("create_a_pcrt: BufferToFile fail\n");
        goto err;
    }

    pcrt_mutex_.lock();
    pcrt_list_.push_back(file_name);
    pcrt_mutex_.unlock();
        
    ret = COMMON_SUCCESS;
    err:{
        if (pkey) {
            EC_KEY_free(pkey);
        }
        if (pub_key) {
            free(pub_key);
        }
        if (pri_key) {
            free(pri_key);
        }
        if (pcrt) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Certificate, pcrt);
        }
        if (buffer) {
            free(buffer);
        }
        if (crt_buffer) {
            free(crt_buffer);
        }
    }
    return ret;
}


int CertificateManage::create_a_rcrt(){
    int ret = COMMON_ERROR;
    Certificate_t* rcrt = NULL;
    EC_KEY* rkey = NULL;
    unsigned char* pri_key = NULL;
    unsigned char* pub_key = NULL;
    unsigned char* crt_buffer = NULL;
    size_t crt_len = 0;
    unsigned char* buffer = NULL;
    size_t blen = 0;
    unsigned long rcrt_end_gmtime = 0;
    string crt_name(RCRTS);
    string file_name;

    if ((rkey = Common::CreateSm2KeyPair()) == NULL) {
        printf("create_a_rcrt: CreateSm2KeyPair rkey fail\n");
        goto err;
    }

    if ((pri_key = Common::get_sm2_private_key(rkey)) == NULL) {
        printf("create_a_rcrt: get_sm2_private_key fail\n");
        goto err;
    }

    if ((pub_key = Common::get_sm2_public_key(rkey)) == NULL) {
        printf("create_a_rcrt: get_sm2_public_key fail\n");
        goto err;
    }

    if((rcrt = CertificateManage::CreateCertificate(e_CertificateType.R_CRT, e_SubjectType.SubjectType_authorizationTicket,
                                                    pub_key, g_rca_hashid8, g_rca_key)) == NULL){
        printf("create_a_rcrt: CreateCertificate rcrt fail\n");
        goto err;
    }
    rcrt_serial_number++;
    rcrt_end_gmtime = Common::get_time_by_diff(rcrt->validityRestrictions.choice.timeStartAndEnd.endValidity);

    if (CertificateManage::CertificateToBuffer(&crt_buffer, &crt_len, pcrt) != COMMON_SUCCESS) {
        printf("create_a_rcrt: CertificateToBuffer fail\n");
        goto err;
    }

    buffer = (unsigned char* )malloc(crt_len + PRIVATE_KEY_LENGTH);
    if (!buffer) {
        printf("create_a_rcrt: malloc buffer fail\n");
        goto err;
    }
    blen = crt_len + PRIVATE_KEY_LENGTH;

    memcpy(buffer, pri_key, PRIVATE_KEY_LENGTH);
    memcpy(buffer+PRIVATE_KEY_LENGTH, crt_buffer, crt_len);

    file_name = Common::ToString(rcrt_end_gmtime) +"_"+ Common::ToString(rcrt_serial_number);
    crt_name+= file_name;
    if (Common::BufferToFile(crt_name.c_str(), buffer, blen) != COMMON_SUCCESS) {
        printf("create_a_rcrt: BufferToFile fail\n");
        goto err;
    }

    rcrt_mutex_.lock();
    rcrt_list_.push_back(file_name);
    rcrt_mutex_.unlock();
        
    ret = COMMON_SUCCESS;
    err:{
        if (rkey) {
            EC_KEY_free(pkey);
        }
        if (pub_key) {
            free(pub_key);
        }
        if (pri_key) {
            free(pri_key);
        }
        if (rcrt) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Certificate, rcrt);
        }
        if (buffer) {
            free(buffer);
        }
        if (crt_buffer) {
            free(crt_buffer);
        }
    }
    return ret;
}


/**
* @}
**/
