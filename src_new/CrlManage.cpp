
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

extern s_CaInfo g_rootca;
extern s_CaInfo g_subrootca;
extern s_CaInfo g_eca;
extern s_CaInfo g_pca;
extern s_CaInfo g_rca;
extern s_CaInfo g_cca;

std::thread CrlManage::crl_manage_thread_;
std::list<std::string> CrlManage::crl_list_;
std::mutex CrlManage::crl_mutex_;
unsigned long CrlManage::crl_serial_number_ = 0;

int CrlManage::CrlToFile(const char* filename, Crl_t *crl){

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

int CrlManage::CrlToBuffer(unsigned char** buffer, size_t* blen, Crl_t *crl){
    if (!crl) {
        return COMMON_NULL_POINT;
    }

    asn_enc_rval_t er = uper_encode(&asn_DEF_Crl, crl, Common::uper_callback, NULL);
    if(er.encoded == -1) {
        fprintf(stderr, "CrlToBuffer: uper_encode Cannot encode %s\n", er.failed_type->name);
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
            fprintf(stderr, "CrlToBuffer: uper_encode_to_buffer Cannot encode %s\n", ec.failed_type->name);
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
    asn_enc_rval_t er = uper_encode(&asn_DEF_ToBeSignedCrl, tbs, Common::uper_callback, NULL);
    if(er.encoded == -1) {
        fprintf(stderr, "CrlToBuffer: uper_encode Cannot encode %s\n", er.failed_type->name);
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
            fprintf(stderr, "CrlToBuffer: uper_encode_to_buffer Cannot encode %s\n", ec.failed_type->name);
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

Crl_t* CrlManage::CreateCRL(bool is_first, unsigned char* hashid10, unsigned long crl_start_difftime){
    int ret = COMMON_ERROR;
    Crl_t *crl = NULL;
    crl = (Crl_t*)calloc(1, sizeof(Crl_t));
    if (!crl) {
        printf("CreateCRL: calloc() crl failed\n");
        goto err;
    }

    crl->signature.present = Signature_PR_signature;
    crl->signature.choice.signature.buf = (uint8_t* )malloc(SIGNATURE_LENGTH);
    memset(crl->signature.choice.signature.buf, 0x00, SIGNATURE_LENGTH);
    crl->signature.choice.signature.size = SIGNATURE_LENGTH;

    crl->signerInfo.present = SignerInfo_PR_certificateDigestWithSM3;
    crl->signerInfo.choice.certificateDigestWithSM3.buf = (uint8_t* )malloc(CERTIFICATE_DGST_WITH_SM3_LENGTH);
    memcpy(crl->signerInfo.choice.certificateDigestWithSM3.buf, g_subrootca.hashid8, CERTIFICATE_DGST_WITH_SM3_LENGTH);
    crl->signerInfo.choice.certificateDigestWithSM3.size = CERTIFICATE_DGST_WITH_SM3_LENGTH;

    crl->unsignedCrl.caId.buf = (uint8_t* )malloc(CERTIFICATE_DGST_WITH_SM3_LENGTH);
    memcpy(crl->unsignedCrl.caId.buf, g_cca.hashid8, CERTIFICATE_DGST_WITH_SM3_LENGTH);
    crl->unsignedCrl.caId.size = CERTIFICATE_DGST_WITH_SM3_LENGTH;

    if (is_first) {
        crl->unsignedCrl.crlSerial = 0;
    }else{
        crl->unsignedCrl.crlSerial = ++crl_serial_number_;
    }
    crl->unsignedCrl.startPeriod = crl_start_difftime;
    crl->unsignedCrl.issueDate = Common::get_difftime_by_now();
    crl->unsignedCrl.nextCrl = Common::get_difftime_by_now();

    crl->unsignedCrl.type.present = CrlType_PR_idOnly;
    crl->unsignedCrl.type.choice.idOnly.buf =  (uint8_t* )malloc(UNSIGNED_CRL_HASHID_LENGTH);
    memcpy(crl->unsignedCrl.type.choice.idOnly.buf, hashid10, UNSIGNED_CRL_HASHID_LENGTH);
    crl->unsignedCrl.type.choice.idOnly.size = UNSIGNED_CRL_HASHID_LENGTH;

    crl->version = CRL_VERSION;

    if(CrlSign(g_cca.key, crl) != COMMON_SUCCESS){
        printf("CreateCRL: CrlSign fail\n");
        goto err;
    }

    //xer_fprint(stdout, &asn_DEF_Crl, crl);
    ret = COMMON_SUCCESS;
    err:{
        if (crl && (ret != COMMON_SUCCESS)) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Crl, crl);
        }
    }
    return crl;
}

int CrlManage::CrlSign(EC_KEY* key, Crl_t* crl){
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

int CrlManage::CrlVerify(EC_KEY* key, Crl_t* crl){
    //no need for now
    return 0;
}


int CrlManage::Init(){
    if (CrlManage::init_crl_list() != COMMON_SUCCESS) {
        printf("Init: init_crl_list fail\n");
        return COMMON_ERROR;
    }
    return COMMON_SUCCESS;
}

void CrlManage::Start(){
    crl_manage_thread_ = std::thread(CrlManage::crl_manage);
    crl_manage_thread_.detach();
}

void CrlManage::crl_manage(){
    printf("crl_manage thread start\n");
    while (true) {
        if (Common::get_hour_now() == 2) {
            crl_mutex_.lock();
            for (std::list<std::string>::iterator i = crl_list_.begin(); i != crl_list_.end(); ){
                std::string name(*i);
                if (strtoul(name.substr(0, name.find("_")).c_str(), NULL, 10) < Common::get_time_now()){
                    crl_list_.erase(i++);
                    name = CRL_FILENAME + name;
                    remove(name.c_str());
                }else{
                    i++;
                }
                usleep(1);
            }
            crl_mutex_.unlock();
        }
        sleep(1);
    }
    printf("crl_manage thread dead\n");
}

int CrlManage::init_crl_list(){
    printf("CrlManage init_crl_list start\n");
    DIR* dir = opendir(CRL_FILENAME);
    dirent* p = NULL;
    crl_list_.clear();
    unsigned long crl_size = 0;
    while((p = readdir(dir)) != NULL){
        if(p->d_name[0] != '.'){
            std::string name(p->d_name);
            crl_list_.push_back(name);
            unsigned long sn = strtoul(name.substr(name.find("_") + 1).c_str(), NULL, 10);
            crl_serial_number_ = sn > crl_serial_number_? sn : crl_serial_number_;
            crl_size++;
        }
    }
    closedir(dir);
    printf("CrlManage crl_list size: %d\n",  crl_list_.size());
    if (crl_serial_number_ == 0 && crl_size ==0) {
        Crl_t* crl = NULL;
        unsigned char hashid10[10];
        memset(hashid10, 0x00, 10);
        crl = CrlManage::CreateCRL(true, hashid10, Common::get_difftime_by_now());
        if (!crl) {
            printf("init_crl_list: Create first crl fail\n");
            return COMMON_ERROR;
        }
        //xer_fprint(stdout, &asn_DEF_Crl, crl);
        std::string file_name(CRL_FILENAME);
        std::string list_name;
        list_name = Common::UnsignedLongToString(Common::get_time_by_diff(Common::get_difftime_by_years(CA_CRT_VALIDITY_PERIOD_YEARS))) 
                         +"_" + Common::UnsignedLongToString(crl->unsignedCrl.crlSerial);

        file_name += list_name;
        if (CrlManage::CrlToFile(file_name.c_str(), crl) != COMMON_SUCCESS) {
            printf("init_crl_list: CrlToFile fail\n");
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Crl, crl);
            return COMMON_ERROR;
        }
        crl_list_.push_back(list_name);
    }
    printf("CrlManage init_crl_list end\n");
    return COMMON_SUCCESS;
}

void CrlManage::set_crl_list(std::string name){
    crl_mutex_.lock();
    crl_list_.push_back(name);
    crl_mutex_.unlock();
}

int CrlManage::get_crls(unsigned char** buffer, size_t* blen, size_t* crl_num){
    std::string name;
    int num = 0;
    int len = 0;
    std::lock_guard<std::mutex> lck(crl_mutex_);
    //crl length is not sure, for now is 79, size length = 2, so one crl is 81 bits  
    unsigned char *buff = (unsigned char*)malloc(81 * crl_list_.size());
    if (!buff) {
        printf("get_crls: malloc buff fail\n");
        return COMMON_ERROR;
    }

    for (std::list<std::string>::iterator i = crl_list_.begin(); i != crl_list_.end(); i++) {
        name = *i;
        unsigned char* crl_buffer = NULL;
        size_t crl_buffer_size = 0;
        unsigned long crl_end_time = 0;
        crl_end_time = strtoul(name.substr(0, name.find_first_of("_")).c_str(), NULL ,10);
        name = CRL_FILENAME + name;

        if (true){//(crl_end_time > Common::get_time_now()) {
            if (Common::FileToBuffer(name.c_str(), &crl_buffer, &crl_buffer_size) != COMMON_SUCCESS) {
                printf("get_crls: FileToBuffer fail\n");
                free(buff);
                return COMMON_ERROR;
            }
            unsigned char* clen = Common::IntToUnsignedChar(crl_buffer_size);
            memcpy(buff+len, clen+2, 2);
            len+=2;
            free(clen);
            memcpy(buff+len, crl_buffer, crl_buffer_size);
            len+=crl_buffer_size;
            num++;
        }
        free(crl_buffer);
    }
    *buffer = buff;
    *blen = len;
    *crl_num = num;

    return COMMON_SUCCESS;
}



/**
* @}
**/

