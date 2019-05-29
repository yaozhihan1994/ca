/***********************************************
* @addtogroup Nebula
* @{
* @file  : CertMng.cpp
* @brief :
* @date  : 2019-05-13
***********************************************/
 
//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------


#include "CertMng.h"

extern s_CaInfo g_rootca;
extern s_CaInfo g_subrootca;
extern s_CaInfo g_eca;
extern s_CaInfo g_pca;
extern s_CaInfo g_rca;
extern s_CaInfo g_cca;

std::list<std::string> CertMng::pcrt_list_;
std::mutex CertMng::pcrt_mutex_;

std::list<std::string> CertMng::rcrt_list_;
std::mutex CertMng::rcrt_mutex_;

std::thread CertMng::pcrt_manage_thread_;
std::thread CertMng::rcrt_manage_thread_;

unsigned long CertMng::pcrt_serial_number_ = 0;
unsigned long CertMng::rcrt_serial_number_ = 0;

CertMng::CertMng(){
}

CertMng::~CertMng(){
}

int CertMng::CertificateToFile(const char* filename, Certificate_t *crt){
    if (!filename || !crt) {
        return COMMON_INVALID_PARAMS;
    }

    int ret = COMMON_ERROR;
    unsigned char* buffer = NULL;
    size_t blen = 0;

    if (COMMON_SUCCESS != CertMng::CertificateToBuffer(&buffer, &blen, crt)) {
        printf("CertificateToFile: CertificateToBuffer fail\n");
        goto err;
    }

    if(CertOp::BufferToFile(filename, buffer, blen) != COMMON_SUCCESS){
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

Certificate_t* CertMng::FileToCertificate(const char* filename){
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

int CertMng::CertificateToDer(unsigned char** buffer, size_t* blen, Certificate_t *crt){
   if (!crt || !blen) {
        return COMMON_INVALID_PARAMS;
    }
    asn_enc_rval_t er = der_encode(&asn_DEF_Certificate, crt, CertOp::uper_callback, NULL);
    if(er.encoded == -1) {
        fprintf(stderr, "CertificateToDer: der_encode Cannot encode %s\n", er.failed_type->name);
        return COMMON_ERROR;
    } else {
        int len = er.encoded;
        unsigned char* buff = (unsigned char*)malloc(len);
        if (!buff) {
            printf("CertificateToDer: malloc buff fail\n");
            return COMMON_ERROR;
        }
        asn_enc_rval_t ec = der_encode_to_buffer(&asn_DEF_Certificate, (void *)crt, (void*)buff, len);
        if(ec.encoded == -1) {
            fprintf(stderr, "CertificateToDer: der_encode_to_buffer Cannot encode %s\n", ec.failed_type->name);
            if (buff) {
                free(buff);
            }
            return COMMON_ERROR;
        } else {
        *blen = ec.encoded;
        *buffer = buff;
        }
        return COMMON_SUCCESS;
    }
}

Certificate_t* CertMng::DerToCertificate(unsigned char* buffer, size_t blen){
    if (!buffer) {
        return NULL;
    }

    Certificate_t* crt = NULL;
    asn_dec_rval_t dr = ber_decode(0, &asn_DEF_Certificate, (void **)(&crt), (void *)buffer, blen);

    if(dr.code != RC_OK){
        printf("DerToCertificate: der_decode_complete fail\n");
        return NULL;
    }
    return crt;
}

int CertMng::CertificateToBuffer(unsigned char** buffer, size_t* blen, Certificate_t *crt){
    if (!crt ||!blen) {
        return COMMON_INVALID_PARAMS;
    }
    asn_enc_rval_t er = uper_encode(&asn_DEF_Certificate, crt, CertOp::uper_callback, NULL);
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

int CertMng::get_sign_der_buffer(Certificate_t* crt, unsigned char** buffer, size_t* blen){
    if (!crt || !blen) {
        return COMMON_INVALID_PARAMS;
    }    
    asn_enc_rval_t ec;
    asn_enc_rval_t er;
    //der version
    size_t version_len = 0;
    er = der_encode(&asn_DEF_Uint8, (void *)&(crt->version), 0, NULL);
    if(er.encoded == -1) {
        fprintf(stderr, "get_sign_der_buffer: der_encode_to_buffer Cannot encode %s\n", ec.failed_type->name);
        return COMMON_ERROR;
    }  
    version_len = er.encoded;
    unsigned char version_buff[version_len];
    ec = der_encode_to_buffer(&asn_DEF_Uint8, (void *)&(crt->version), (void*)(version_buff), version_len);
    if(ec.encoded == -1) {
        fprintf(stderr, "get_sign_der_buffer: der_encode_to_buffer Cannot encode %s\n", ec.failed_type->name);
        return COMMON_ERROR;
    } 

    //der signerInfo
    size_t signerInfo_len = 0;
    er = der_encode(&asn_DEF_SignerInfo, (void *)(crt->signerInfo), 0, NULL);
    if(er.encoded == -1) {
        fprintf(stderr, "get_sign_der_buffer: der_encode_to_buffer Cannot encode %s\n", ec.failed_type->name);
        return COMMON_ERROR;
    }  
    signerInfo_len = er.encoded;
    unsigned char signerInfo_buff[signerInfo_len];
    ec = der_encode_to_buffer(&asn_DEF_SignerInfo, (void *)(crt->signerInfo), (void*)(signerInfo_buff), signerInfo_len);
    if(ec.encoded == -1) {
        fprintf(stderr, "get_sign_der_buffer: der_encode_to_buffer Cannot encode %s\n", ec.failed_type->name);
        return COMMON_ERROR;
    }  

    //der subjectInfo
    size_t subjectInfo_len = 0;
    er = der_encode(&asn_DEF_SubjectInfo, (void *)&(crt->subjectInfo), 0, NULL);
    if(er.encoded == -1) {
        fprintf(stderr, "get_sign_der_buffer: der_encode_to_buffer Cannot encode %s\n", ec.failed_type->name);
        return COMMON_ERROR;
    }  
    subjectInfo_len = er.encoded;
    unsigned char subjectInfo_buff[subjectInfo_len];
    ec = der_encode_to_buffer(&asn_DEF_SubjectInfo, (void *)&(crt->subjectInfo), (void*)(subjectInfo_buff), subjectInfo_len);
    if(ec.encoded == -1) {
        fprintf(stderr, "get_sign_der_buffer: der_encode_to_buffer Cannot encode %s\n", ec.failed_type->name);
        return COMMON_ERROR;
    }  

    //der subjectAttributes
    size_t subjectAttributes_len = 0;
    er = der_encode(&asn_DEF_SubjectAttribute, (void *)&(crt->subjectAttributes), 0, NULL);
    if(er.encoded == -1) {
        fprintf(stderr, "get_sign_der_buffer: der_encode_to_buffer Cannot encode %s\n", ec.failed_type->name);
        return COMMON_ERROR;
    }  
    subjectAttributes_len = er.encoded;
    unsigned char subjectAttributes_buff[subjectAttributes_len];
    ec = der_encode_to_buffer(&asn_DEF_SubjectAttribute, (void *)&(crt->subjectAttributes), (void*)(subjectAttributes_buff), subjectAttributes_len);
    if(ec.encoded == -1) {
        fprintf(stderr, "get_sign_der_buffer: der_encode_to_buffer Cannot encode %s\n", ec.failed_type->name);
        return COMMON_ERROR;
    }  

    //der validityRestrictions
    size_t validityRestrictions_len = 0;
    er = der_encode(&asn_DEF_ValidityRestriction, (void *)&(crt->validityRestrictions), 0, NULL);
    if(er.encoded == -1) {
        fprintf(stderr, "get_sign_der_buffer: der_encode_to_buffer Cannot encode %s\n", ec.failed_type->name);
        return COMMON_ERROR;
    }  
    validityRestrictions_len = er.encoded;
    unsigned char validityRestrictions_buff[validityRestrictions_len];
    ec = der_encode_to_buffer(&asn_DEF_ValidityRestriction, (void *)&(crt->validityRestrictions), (void*)(validityRestrictions_buff), validityRestrictions_len);
    if(ec.encoded == -1) {
        fprintf(stderr, "get_sign_der_buffer: der_encode_to_buffer Cannot encode %s\n", ec.failed_type->name);
        return COMMON_ERROR;
    }  

    size_t buff_len = version_len+signerInfo_len+subjectInfo_len+subjectAttributes_len+validityRestrictions_len; 
    unsigned char* buff = (unsigned char* )malloc(buff_len);
    if (!buff) {
        printf("get_sign_der_buffer malloc buff fail \n");
        return COMMON_ERROR;
    }
    size_t tmp = 0;
    memcpy(buff+tmp, version_buff, version_len);
    tmp+= version_len;
    memcpy(buff+tmp, signerInfo_buff, signerInfo_len);
    tmp+= signerInfo_len;
    memcpy(buff+tmp, subjectInfo_buff, subjectInfo_len);
    tmp+= subjectInfo_len;
    memcpy(buff+tmp, subjectAttributes_buff, subjectAttributes_len);
    tmp+= subjectAttributes_len;
    memcpy(buff+tmp, validityRestrictions_buff, validityRestrictions_len);

    *buffer = buff;
    *blen = buff_len;
    return COMMON_SUCCESS;
}

Certificate_t* CertMng::BufferToCertificate(unsigned char* buffer, size_t blen){
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

int CertMng::CertificateSign(EC_KEY* key, Certificate_t* crt){

    if (!key || !crt) {
        return COMMON_INVALID_PARAMS;
    }

    int ret = COMMON_ERROR;
    unsigned char* sig = NULL;
    size_t slen = 0;
    unsigned char *msg = NULL;
    size_t mlen = 0;

    if(CertMng::get_sign_der_buffer(crt, &msg, &mlen) != COMMON_SUCCESS){
        printf("CertificateSign: get_sign_der_buffer fail\n");
        goto err;
    }

    if (crt->signature.choice.signature.buf == NULL) {
        crt->signature.present = Signature_PR_signature;
        crt->signature.choice.signature.buf = (uint8_t*)malloc(SIGNATURE_LENGTH);
        crt->signature.choice.signature.size = SIGNATURE_LENGTH;
    }
    if (CertOp::SignData(key, msg, mlen, &sig, &slen) != COMMON_SUCCESS) {
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
int CertMng::CertificateVerify(EC_KEY* key, Certificate_t* crt){
    
    if (!key || !crt) {
        return COMMON_INVALID_PARAMS;
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

    if(CertMng::get_sign_der_buffer(crt, &msg, &mlen) != COMMON_SUCCESS){
        printf("CertificateVerify: get_sign_der_buffer fail\n");
        goto err;
    }

    if (CertOp::VerifySignedData(key, sig, crt->signature.choice.signature.size, msg, mlen) != COMMON_SUCCESS) {
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

Certificate_t* CertMng::CreateCertificate(int ctype, int  stype, unsigned char* public_key, unsigned char* sign_crt_hashid8, EC_KEY* sign_key){
    if (!public_key || !sign_key || (ctype != ROOT_CA_CRT && (!sign_crt_hashid8))) {
        printf("CreateCertificate COMMON_INVALID_PARAMS\n");
        return NULL;
    }
    int ret = COMMON_ERROR;
    Certificate_t* crt = 0;
    std::string subject_name = SUBJECT_INFO_NAME;
    size_t subject_name_len = subject_name.length();
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
    if (ctype == ROOT_CA_CRT) {
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
    memcpy(crt->subjectInfo.subjectName.buf, subject_name.c_str(), subject_name_len);
    crt->subjectInfo.subjectName.size = subject_name_len;

    crt->subjectInfo.subjectType = stype;

    crt->validityRestrictions.present = ValidityRestriction_PR_timeStartAndEnd;
    crt->validityRestrictions.choice.timeStartAndEnd.startValidity = CertOp::get_difftime_by_now();
    if (stype == SubjectType_authorizationTicket) {
        crt->validityRestrictions.choice.timeStartAndEnd.endValidity = CertOp::get_difftime_by_days(DEVICE_CRT_VALIDITY_PERIOD_DAYS);
    }else{// root ca // othrer ca
        crt->validityRestrictions.choice.timeStartAndEnd.endValidity = CertOp::get_difftime_by_years(CA_CRT_VALIDITY_PERIOD_YEARS);
    }

    crt->version = CERTIFICATE_VERSION;

    if(COMMON_SUCCESS != CertMng::CertificateSign(sign_key, crt)){
        printf("CreateCertificate CertificateSign fail\n");
        goto err;
    }

    ret = COMMON_SUCCESS;
//  xer_fprint(stdout, &asn_DEF_Certificate, crt);
    err:{
        if (sig) {
            free(sig);
        }
        if (crt && (ret != COMMON_SUCCESS)) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Certificate, crt);
        }
    }
    return crt;
}

void CertMng::pcrt_manage(){

    while (true) {
        if (pcrt_list_.size() < PCRT_POOL) {
            if(CertMng::create_a_pcrt() != COMMON_SUCCESS){
                printf("pcrt_manage: create_a_pcrt fail\n");
                break;
            }
        }

        if (CertOp::get_hour_now() == 2) {
            pcrt_mutex_.lock();
            for (std::list<std::string>::iterator i = pcrt_list_.begin(); i != pcrt_list_.end(); ){
                std::string name(*i);
                if (strtoul(name.substr(0, name.find("_")).c_str(), NULL, 10) < CertOp::get_time_now()){
                    pcrt_list_.erase(i++);
                    name = PCRTS + name;
                    remove(name.c_str());
                }else{
                    i++;
                }
                usleep(1);
            }
            pcrt_mutex_.unlock();
        }
        usleep(1);
    }
    printf("pcrt_manage thread dead\n");
}

void CertMng::rcrt_manage(){

    while (true) {
        if (rcrt_list_.size() < RCRT_POOL) {
            if(CertMng::create_a_rcrt() != COMMON_SUCCESS){
                printf("rcrt_manage: create_a_rcrt fail\n");
                break;
            }
        }

        if (CertOp::get_hour_now() == 2) {
            rcrt_mutex_.lock();
            for (std::list<std::string>::iterator i = rcrt_list_.begin(); i != rcrt_list_.end(); ){
                std::string name(*i);
                if (strtoul(name.substr(0, name.find("_")).c_str(), NULL, 10) < CertOp::get_time_now()){
                    rcrt_list_.erase(i++);
                    name = RCRTS + name;
                    remove(name.c_str());
                }else{
                    i++;
                }
                usleep(1);
            }
            rcrt_mutex_.unlock();
        }
        usleep(1);
    }
    printf("rcrt_manage thread dead\n");
}

int CertMng::get_pcrt_and_pkey(unsigned char** crt, size_t* clen, unsigned char** key, size_t* klen){
    if (!clen || !klen) {
        printf("get_pcrt_and_pkey COMMON_INVALID_PARAMS \n");
        return COMMON_INVALID_PARAMS;
    }
    int ret = COMMON_ERROR;
    unsigned char* buffer = NULL;
    size_t blen = 0;
    unsigned char* pcrt = NULL;
    size_t pcrt_len = 0;
    unsigned char* pkey = NULL;
    size_t pkey_len = 0;
    std::lock_guard<std::mutex> lck(pcrt_mutex_);
    for (std::list<std::string>::iterator i = pcrt_list_.begin(); i != pcrt_list_.end(); ) {
        std::string name = *i;
        //end_time > now ? 
        if ( strtoul(name.substr(0, name.find("_")).c_str(), NULL, 10) > CertOp::get_time_now() ) {
            name = PCRTS + name;
            if(CertOp::FileToBuffer(name.c_str(), &buffer, &blen) != COMMON_SUCCESS){
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

            *crt = pcrt;
            *clen = pcrt_len;
            *key = pkey;
            *klen = pkey_len;

            pcrt_list_.erase(i++);
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

int CertMng::get_rcrt_and_rkey(unsigned char** crt, size_t* clen, unsigned char** key, size_t* klen){

    if (!clen || !klen) {
        printf("get_rcrt_and_rkey COMMON_INVALID_PARAMS \n");
        return COMMON_INVALID_PARAMS;
    }
    int ret = COMMON_ERROR;
    unsigned char* buffer = NULL;
    size_t blen = 0;
    unsigned char* rcrt = NULL;
    size_t rcrt_len = 0;
    unsigned char* rkey = NULL;
    size_t rkey_len = 0;

    std::lock_guard<std::mutex> lck(rcrt_mutex_);
    for (std::list<std::string>::iterator i = rcrt_list_.begin(); i != rcrt_list_.end(); ) {
        std::string name = *i;
        //end_time > now ? 
        if ( strtoul(name.substr(0, name.find("_")).c_str(), NULL, 10) > CertOp::get_time_now() ) {
            name = RCRTS + name;
            if(CertOp::FileToBuffer(name.c_str(), &buffer, &blen) != COMMON_SUCCESS){
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

            *crt = rcrt;
            *clen = rcrt_len;
            *key = rkey;
            *klen = rkey_len;

            rcrt_list_.erase(i++);
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

int CertMng::Init(){
    if (CertMng::init_pcrt_list() != COMMON_SUCCESS) {
        printf("Init: init_pcrt_list fail\n");
        return COMMON_ERROR;
    }
    if (CertMng::init_rcrt_list() != COMMON_SUCCESS) {
        printf("Init: init_rcrt_list fail\n");
        return COMMON_ERROR;
    }
    return COMMON_SUCCESS;
}


void CertMng::Start(){
    pcrt_manage_thread_ = std::thread(CertMng::pcrt_manage);
    pcrt_manage_thread_.detach();
    rcrt_manage_thread_ = std::thread(CertMng::rcrt_manage);
    rcrt_manage_thread_.detach();
}

int CertMng::init_pcrt_list(){
    printf("CertificateManage init_pcrt_list start\n");
    DIR* dir = opendir(PCRTS);
    dirent* p = NULL;
    pcrt_list_.clear();
    while((p = readdir(dir)) != NULL){
        if(p->d_name[0] != '.'){
            std::string name(p->d_name);
            pcrt_list_.push_back(name);
            unsigned long sn = strtoul(name.substr(name.find("_") + 1).c_str(), NULL, 10);
            pcrt_serial_number_ = sn > pcrt_serial_number_? sn : pcrt_serial_number_;
        }
    }
    closedir(dir);
    printf("CertificateManage pcrt_list_ size: %d\n",  pcrt_list_.size());
    printf("CertificateManage init_pcrt_list end\n");
    return COMMON_SUCCESS;
}

int CertMng::init_rcrt_list(){
    printf("CertificateManage init_rcrt_list start\n");
    DIR* dir = opendir(RCRTS);
    dirent* p = NULL;
    rcrt_list_.clear();
    while((p = readdir(dir)) != NULL){
        if(p->d_name[0] != '.'){
            std::string name(p->d_name);
            rcrt_list_.push_back(name);
            unsigned long sn = strtoul(name.substr(name.find("_") + 1).c_str(), NULL, 10);
            rcrt_serial_number_ = sn > rcrt_serial_number_? sn : rcrt_serial_number_;
        }
    }
    closedir(dir);
    printf("CertificateManage rcrt_list_ size: %d\n",  rcrt_list_.size());
    printf("CertificateManage init_rcrt_list end\n");
    return COMMON_SUCCESS;
}

int CertMng::create_a_pcrt(){
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
    std::string crt_name(PCRTS);
    std::string file_name;

    if ((pkey = CertOp::CreateSm2KeyPair()) == NULL) {
        printf("create_a_pcrt: CreateSm2KeyPair pkey fail\n");
        goto err;
    }

    if ((pri_key = CertOp::get_sm2_private_key(pkey)) == NULL) {
        printf("create_a_pcrt: get_sm2_private_key fail\n");
        goto err;
    }

    if ((pub_key = CertOp::get_sm2_public_key(pkey)) == NULL) {
        printf("create_a_pcrt: get_sm2_public_key fail\n");
        goto err;
    }

//  CertOp::print_buffer(pri_key, 32);
//  CertOp::print_buffer(pub_key, 64);

    if((pcrt = CertMng::CreateCertificate(P_CRT, SubjectType_authorizationTicket,
                                                    pub_key, g_pca.hashid8, g_pca.key)) == NULL){
        printf("create_a_pcrt: CreateCertificate pcrt fail\n");
        goto err;
    }
    pcrt_serial_number_++;
    pcrt_end_gmtime = CertOp::get_time_by_diff(pcrt->validityRestrictions.choice.timeStartAndEnd.endValidity);

    if (CertMng::CertificateToBuffer(&crt_buffer, &crt_len, pcrt) != COMMON_SUCCESS) {
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

    file_name = CertOp::UnsignedLongToString(pcrt_end_gmtime) +"_"+ CertOp::UnsignedLongToString(pcrt_serial_number_);
    crt_name+= file_name;
    if (CertOp::BufferToFile(crt_name.c_str(), buffer, blen) != COMMON_SUCCESS) {
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


int CertMng::create_a_rcrt(){
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
    std::string crt_name(RCRTS);
    std::string file_name;

    if ((rkey = CertOp::CreateSm2KeyPair()) == NULL) {
        printf("create_a_rcrt: CreateSm2KeyPair rkey fail\n");
        goto err;
    }

    if ((pri_key = CertOp::get_sm2_private_key(rkey)) == NULL) {
        printf("create_a_rcrt: get_sm2_private_key fail\n");
        goto err;
    }

    if ((pub_key = CertOp::get_sm2_public_key(rkey)) == NULL) {
        printf("create_a_rcrt: get_sm2_public_key fail\n");
        goto err;
    }

//  CertOp::print_buffer(pri_key, 32);
//  CertOp::print_buffer(pub_key, 64);

    if((rcrt = CertMng::CreateCertificate(R_CRT, SubjectType_authorizationTicket,
                                                    pub_key, g_rca.hashid8, g_rca.key)) == NULL){
        printf("create_a_rcrt: CreateCertificate rcrt fail\n");
        goto err;
    }
    rcrt_serial_number_++;
    rcrt_end_gmtime = CertOp::get_time_by_diff(rcrt->validityRestrictions.choice.timeStartAndEnd.endValidity);

    if (CertMng::CertificateToBuffer(&crt_buffer, &crt_len, rcrt) != COMMON_SUCCESS) {
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

    file_name = CertOp::UnsignedLongToString(rcrt_end_gmtime) +"_"+ CertOp::UnsignedLongToString(rcrt_serial_number_);
    crt_name+= file_name;
    if (CertOp::BufferToFile(crt_name.c_str(), buffer, blen) != COMMON_SUCCESS) {
        printf("create_a_rcrt: BufferToFile fail\n");
        goto err;
    }

    rcrt_mutex_.lock();
    rcrt_list_.push_back(file_name);
    rcrt_mutex_.unlock();
        
    ret = COMMON_SUCCESS;
    err:{
        if (rkey) {
            EC_KEY_free(rkey);
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

