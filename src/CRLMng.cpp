
/***********************************************
* @addtogroup Nebula
* @{
* @file  : CRLMng.cpp
* @brief :
* @date  : 2019-05-13
***********************************************/
 
//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------

#include "CRLMng.h"

extern s_CaInfo g_rootca;
extern s_CaInfo g_subrootca;
extern s_CaInfo g_eca;
extern s_CaInfo g_pca;
extern s_CaInfo g_rca;
extern s_CaInfo g_cca;

std::thread CRLMng::crl_manage_thread_;
std::map<std::string, std::array<unsigned char, 10>> CRLMng::crl_map_;
std::mutex CRLMng::crl_mutex_;
std::mutex CRLMng::crl_serial_mutex_;
unsigned long CRLMng::crl_serial_number_ = 0;

CRLMng::CRLMng(){
}

CRLMng::~CRLMng(){
}

int CRLMng::CrlToFile(const char* filename, Crl_t *crl){

    if (!filename || !crl) {
        return COMMON_INVALID_PARAMS;
    }

    int ret = COMMON_ERROR;
    unsigned char* buffer = NULL;
    size_t blen = 0;
    if (COMMON_SUCCESS != CRLMng::CrlToBuffer(&buffer, &blen, crl)) {
        printf("CrlToFile: CrlToBuffer fail\n");
        goto err;
    }

    if (COMMON_SUCCESS != CertOp::BufferToFile(filename, buffer, blen)) {
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

Crl_t* CRLMng::FileToCrl(const char* filename){
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

int CRLMng::CrlToBuffer(unsigned char** buffer, size_t* blen, Crl_t *crl){
    if (!crl || !blen) {
        return COMMON_INVALID_PARAMS;
    }

    asn_enc_rval_t er = uper_encode(&asn_DEF_Crl, crl, CertOp::uper_callback, NULL);
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

Crl_t* CRLMng::BufferToCrl(unsigned char* buffer, size_t blen){
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

int CRLMng::ToBeSignedCrlToDer(unsigned char** buffer, size_t* blen, ToBeSignedCrl_t *tbs){
    if (!tbs || !blen) {
        return COMMON_INVALID_PARAMS;
    }
    asn_enc_rval_t er = der_encode(&asn_DEF_ToBeSignedCrl, tbs, CertOp::uper_callback, NULL);
    if(er.encoded == -1) {
        fprintf(stderr, "CrlToBuffer: der_encode Cannot encode %s\n", er.failed_type->name);
        return COMMON_ERROR;
    } 
    else {
        int len = er.encoded;
        unsigned char* buff = (unsigned char*)malloc(len);
        if (!buff) {
            printf("CrlToBuffer: malloc buff fail\n");
            return COMMON_ERROR;
        }
        asn_enc_rval_t ec = der_encode_to_buffer(&asn_DEF_ToBeSignedCrl, (void *)tbs, (void*)buff, len);
        if(ec.encoded == -1) {
            fprintf(stderr, "CrlToBuffer: uper_encode_to_buffer Cannot encode %s\n", ec.failed_type->name);
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

Crl_t* CRLMng::CreateCRL(bool is_first, unsigned char* hashid10, unsigned long crl_start_difftime){
    if (!hashid10) {
        return NULL;
    }

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
    crl->unsignedCrl.issueDate = CertOp::get_difftime_by_now();
    crl->unsignedCrl.nextCrl = CertOp::get_difftime_by_now();

    crl->unsignedCrl.type.present = CrlType_PR_idOnly;
    crl->unsignedCrl.type.choice.idOnly.buf =  (uint8_t* )malloc(UNSIGNED_CRL_HASHID_LENGTH);
    memcpy(crl->unsignedCrl.type.choice.idOnly.buf, hashid10, UNSIGNED_CRL_HASHID_LENGTH);
    crl->unsignedCrl.type.choice.idOnly.size = UNSIGNED_CRL_HASHID_LENGTH;

    crl->version = CRL_VERSION;

    if(CrlSign(g_cca.key, crl) != COMMON_SUCCESS){
        printf("CreateCRL: CrlSign fail\n");
        goto err;
    }

    if (set_crl_serial_number(crl_serial_number_) != COMMON_SUCCESS){
        printf("CreateCRL: set_crl_serial_number fail\n");
        goto err;
    }
//  xer_fprint(stdout, &asn_DEF_Crl, crl);
    ret = COMMON_SUCCESS;
    err:{
        if (crl && (ret != COMMON_SUCCESS)) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Crl, crl);
        }
    }
    return crl;
}

int CRLMng::CrlSign(EC_KEY* key, Crl_t* crl){
    if (!key || !crl) {
        return COMMON_INVALID_PARAMS;
    }

    int ret = COMMON_ERROR;
    const char* id = SM2_USER_ID;
    unsigned char* buffer = NULL;
    size_t blen = 0;
    ECDSA_SIG* signature = NULL;
//  unsigned char* sig = NULL;
//  size_t slen = 0;

    const BIGNUM* r = NULL;
    const BIGNUM* s = NULL;
    unsigned char cr[32]={};
    unsigned char cs[32]={};
    unsigned char* sig = NULL;

    if(ToBeSignedCrlToDer(&buffer, &blen, &(crl->unsignedCrl)) != COMMON_SUCCESS){
        printf("CrlSign: ToBeSignedCrlToDer fail\n");
        goto err;
    }

    signature = SM2_do_sign(key, EVP_sm3(), id, buffer, blen);
    if (!signature) {
        printf("CrlSign: SM2_do_sign fail\n");
        goto err;
    }

    ECDSA_SIG_get0(signature, &r, &s);
    if (!r || !s) {
        printf("CrlSign: ECDSA_SIG_get0 fail\n");
        goto err;
    }

    if (!BN_bn2bin(r, cr)) {
        printf("CrlSign BN_bn2bin failed\n");
        goto err;
    }

    if (!BN_bn2bin(s, cs)) {
        printf("CrlSign BN_bn2bin failed\n");
        goto err;
    }

    sig = (unsigned char* )malloc(64);
    if (!sig) {
        printf("CrlSign malloc sig failed\n");
        goto err;
    }

    memcpy(sig, cr, 32);
    memcpy(sig+32, cs, 32);

//  slen = i2d_ECDSA_SIG(signature, &sig);
//  if (slen == 0) {
//      printf("CrlSign: i2d_ECDSA_SIG fail\n");
//      goto err;
//  }
    if (crl->signature.choice.signature.buf == NULL) {
        crl->signature.choice.signature.buf = (uint8_t* )malloc(64);
        crl->signature.choice.signature.size = 64;
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

int CRLMng::CrlVerify(EC_KEY* key, Crl_t* crl){
    //no need for now
    return 0;
}


int CRLMng::Init(){
    if (CRLMng::init_crl_map() != COMMON_SUCCESS) {
        printf("Init: init_crl_list fail\n");
        return COMMON_ERROR;
    }
    return COMMON_SUCCESS;
}

void CRLMng::Start(){
    crl_manage_thread_ = std::thread(CRLMng::crl_manage);
    crl_manage_thread_.detach();
}

void CRLMng::crl_manage(){
    printf("crl_manage thread start\n");
    while (true) {
        if (CertOp::get_hour_now() == 2) {
            crl_mutex_.lock();
            for (std::map<std::string, std::array<unsigned char, 10>>::iterator i = crl_map_.begin(); i != crl_map_.end(); ){
                std::string name(i->first);
                if (strtoul(name.substr(0, name.find("_")).c_str(), NULL, 10) < CertOp::get_time_now()){
                    crl_map_.erase(i++);
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

int CRLMng::init_crl_map(){
    printf("CrlManage init_crl_map start\n");
    DIR* dir = opendir(CRL_FILENAME);
    dirent* p = NULL;
    crl_map_.clear();
    crl_serial_number_ = get_crl_serial_number();
    while((p = readdir(dir)) != NULL){
        if(p->d_name[0] != '.'){
            std::string map_name(p->d_name);
            std::string file_name(CRL_FILENAME);
            file_name += map_name;
            Crl_t* crl = NULL;
            if ((crl = CRLMng::FileToCrl(file_name.c_str())) == NULL) {
                printf("init_crl_map: FileToCrl fail\n");
                return COMMON_ERROR;
            }
            std::array<unsigned char, 10> arr {};
            memcpy(arr.data(), crl->unsignedCrl.type.choice.idOnly.buf, 10);
            crl_map_.insert(std::pair<std::string,std::array<unsigned char, 10>>(map_name, arr));
            if (crl) {
                ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Crl, crl);
            }
        }
    }
    closedir(dir);
    std::cout<<"CrlManage crl_list size: "<<crl_map_.size()<<std::endl;
    if (crl_serial_number_ == 0 && crl_map_.size() ==0) {
        Crl_t* crl = NULL;
        unsigned char hashid10[10];
        memset(hashid10, 0x00, 10);
        crl = CRLMng::CreateCRL(true, hashid10, CertOp::get_difftime_by_now());
        if (!crl) {
            printf("init_crl_list: Create first crl fail\n");
            return COMMON_ERROR;
        }
        //xer_fprint(stdout, &asn_DEF_Crl, crl);
        std::string file_name(CRL_FILENAME);
        std::string map_name;
        map_name = CertOp::UnsignedLongToString(CertOp::get_time_by_diff(CertOp::get_difftime_by_years(CA_CRT_VALIDITY_PERIOD_YEARS))) 
                         +"_" + CertOp::UnsignedLongToString(crl->unsignedCrl.crlSerial);

        file_name += map_name;
        if (CRLMng::CrlToFile(file_name.c_str(), crl) != COMMON_SUCCESS) {
            printf("init_crl_list: CrlToFile fail\n");
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Crl, crl);
            return COMMON_ERROR;
        }
        std::array<unsigned char, 10> arr {};
        memcpy(arr.data(), hashid10, 10);
        crl_map_.insert(std::pair<std::string, std::array<unsigned char, 10>>(map_name, arr));
    }
    printf("CrlManage init_crl_map end\n");
    return COMMON_SUCCESS;
}

void CRLMng::set_crl_map(std::string name, unsigned char* hashid10){
    if (!hashid10) {
        printf("set_crl_map COMMON_INVALID_PARAMS\n");
        return;
    }
    std::array<unsigned char, 10> arr{};
    memcpy(arr.data(), hashid10, 10);
    std::lock_guard<std::mutex> lck(crl_mutex_);
    crl_map_.insert(std::pair<std::string, std::array<unsigned char, 10>>(name, arr));
}

int CRLMng::get_crls(unsigned char** buffer, size_t* blen, size_t* crl_num){
    if (!crl_num || !blen) {
        printf("get_crls COMMON_INVALID_PARAMS\n");
        return COMMON_INVALID_PARAMS;
    }
    std::string name;
    int num = 0;
    int len = 0;
    std::lock_guard<std::mutex> lck(crl_mutex_);
    //crl length is not sure, for now is 79, size length = 2, so one crl is 81 bits  
    unsigned char *buff = (unsigned char*)malloc(CRL_MAX_LENGTH * crl_map_.size());
    if (!buff) {
        printf("get_crls: malloc buff fail\n");
        return COMMON_ERROR;
    }

    for (std::map<std::string, std::array<unsigned char, 10>>::iterator i = crl_map_.begin(); i != crl_map_.end(); i++) {
        name = i->first;
        unsigned char* crl_buffer = NULL;
        size_t crl_buffer_size = 0;
        unsigned long crl_end_time = 0;
        crl_end_time = strtoul(name.substr(0, name.find_first_of("_")).c_str(), NULL ,10);
        name = CRL_FILENAME + name;
        if (crl_end_time > CertOp::get_time_now()) {
            if (CertOp::FileToBuffer(name.c_str(), &crl_buffer, &crl_buffer_size) != COMMON_SUCCESS) {
                printf("get_crls: FileToBuffer fail\n");
                free(buff);
                return COMMON_ERROR;
            }
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

int CRLMng::check_reported_crl(unsigned char* hashid10){
    if (!hashid10) {
        printf("check_reported_crl: COMMON_INVALID_PARAMS!\n");
        return COMMON_INVALID_PARAMS;
    }
    std::lock_guard<std::mutex> lck(crl_mutex_);
    for (std::map<std::string, std::array<unsigned char, 10>>::iterator i = crl_map_.begin(); i != crl_map_.end(); i++) {
        if (memcmp(hashid10, (i->second).data(), 10) == 0) {
            return COMMON_SUCCESS;
        }
    }
    return COMMON_ERROR;
}


unsigned long CRLMng::get_crl_serial_number(){
    unsigned long sn = 0;
    std::fstream fs;
    fs.open(CRL_SERIAL_NUMBER, std::ios::in);
    if (!fs) {
        printf("set_crl_serial_number: open file: %s Failed!\n", CRL_SERIAL_NUMBER);
        return sn;
    }
    std::string s;
    fs>>s;
    std::stringstream ss;
    ss<<s;
    ss>>sn;
    fs.close();
    return sn;
}

int CRLMng::set_crl_serial_number(unsigned long sn){
    std::lock_guard<std::mutex> lck(crl_serial_mutex_);
    std::fstream fs;
    fs.open(CRL_SERIAL_NUMBER, std::ios::out);
    if (!fs) {
        printf("set_crl_serial_number: open file: %s Failed!\n", CRL_SERIAL_NUMBER);
        return COMMON_ERROR;
    }
    fs<<sn;
    fs.close();
    return COMMON_SUCCESS;
}

/**
* @}
**/

