/***********************************************
* @addtogroup Nebula
* @{
* @file  : Init.cpp
* @brief :
* @date  : 2019-04-25
***********************************************/
 
//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------
  
#include "Init.h"

using namespace std;

int Init(){
  
    int ret = COMMON_ERROR;

    EC_KEY* rootca_key = NULL;
    EC_KEY* subrootca_key = NULL;

    Certificate_t* rootca_crt = NULL;
    Certificate_t* subrootca_crt = NULL;

    if(COMMON_SUCCESS != CreateRootCA()){
        printf("Init: CreateRootCA fail\n");
        goto err;
    }
    printf("Init: CreateRootCA succ\n");
    if(COMMON_SUCCESS != GetCaAndKeyFromFile(ROOTCACRT, ROOTCAKEY, &rootca_crt, &rootca_key)){
        printf("Init: GetCaAndKeyFromFile fail\n");
        goto err;
    }
    printf("Init: GetCaAndKeyFromFile rootCA succ\n");
    if(COMMON_SUCCESS != CreateSubCA(rootca_crt, rootca_key, SubjectType_rootCa, SUBROOTCACRT, SUBROOTCAKEY)){
        printf("Init: CreateSubCA SubRootCa fail\n");
        goto err;
    }
    printf("Init: CreateSubCA succ\n");
    if(COMMON_SUCCESS != GetCaAndKeyFromFile(SUBROOTCACRT, SUBROOTCAKEY, &subrootca_crt, &subrootca_key)){
        printf("Init: GetCaAndKeyFromFile fail\n");
        goto err;
    }
    printf("Init: GetCaAndKeyFromFile subrootCA succ\n");
    if(COMMON_SUCCESS != CreateSubCA(subrootca_crt, subrootca_key, SubjectType_enrollmentAuthority, ECACRT, ECAKEY)){
        printf("Init: CreateSubCA ECA fail\n");
        goto err;
    }
    printf("Init: CreateECA succ\n");
    if(COMMON_SUCCESS != CreateSubCA(subrootca_crt, subrootca_key, SubjectType_authorizationAuthority, PCACRT, PCAKEY)){
        printf("Init: CreateSubCA PCA fail\n");
        goto err;
    }
    printf("Init: CreatePCA succ\n");
    if(COMMON_SUCCESS != CreateSubCA(subrootca_crt, subrootca_key, SubjectType_authorizationAuthority, RCACRT, RCAKEY)){
        printf("Init: CreateSubCA RCA fail\n");
        goto err;
    }
    printf("Init: CreateRCA succ\n");
    if(COMMON_SUCCESS != CreateSubCA(subrootca_crt, subrootca_key, SubjectType_crlSigner, CCACRT, CCAKEY)){
        printf("Init: CreateSubCA CCA fail\n");
        goto err;
    }
    printf("Init: CreateCCA succ\n");

    ret = COMMON_SUCCESS;
    err:{
        if (rootca_crt) {
            ASN_STRUCT_FREE(asn_DEF_Certificate, rootca_crt);
        }
        if (subrootca_crt) {
            ASN_STRUCT_FREE(asn_DEF_Certificate, subrootca_crt);
        }
        if (rootca_key) {
            EC_KEY_free(rootca_key);
        }
        if (subrootca_crt) {
            EC_KEY_free(subrootca_key);
        }
    }
    return ret;
}

int CheckCA(){

     if( access(ROOTCACRT, F_OK) == -1 ){
        printf("CheckCA: %s not exists\n", ROOTCACRT);
        return COMMON_ERROR;
     }
     if( access(ROOTCAKEY, F_OK) == -1 ){
        printf("CheckCA: %s not exists\n", ROOTCAKEY);
        return COMMON_ERROR;
     }
     if( access(SUBROOTCACRT, F_OK) == -1 ){
        printf("CheckCA: %s not exists\n", SUBROOTCACRT);
        return COMMON_ERROR;
     }
     if( access(SUBROOTCAKEY, F_OK) == -1 ){
        printf("CheckCA: %s not exists\n", SUBROOTCAKEY);
        return COMMON_ERROR;
     }
     if( access(ECACRT, F_OK) == -1 ){
        printf("CheckCA: %s not exists\n", ECACRT);
        return COMMON_ERROR;
     }
     if( access(ECAKEY, F_OK) == -1 ){
        printf("CheckCA: %s not exists\n", ECAKEY);
        return COMMON_ERROR;
     }
     if( access(PCACRT, F_OK) == -1 ){
        printf("CheckCA: %s not exists\n", PCACRT);
        return COMMON_ERROR;
     }
     if( access(PCAKEY, F_OK) == -1 ){
        printf("CheckCA: %s not exists\n", PCAKEY);
        return COMMON_ERROR;
     }
     if( access(RCACRT, F_OK) == -1 ){
        printf("CheckCA: %s not exists\n", RCACRT);
        return COMMON_ERROR;
     }
     if( access(RCAKEY, F_OK) == -1 ){
        printf("CheckCA: %s not exists\n", RCAKEY);
        return COMMON_ERROR;
     }
     if( access(CCACRT, F_OK) == -1 ){
        printf("CheckCA: %s not exists\n", CCACRT);
        return COMMON_ERROR;
     }
     if( access(CCAKEY, F_OK) == -1 ){
        printf("CheckCA: %s not exists\n", CCAKEY);
        return COMMON_ERROR;
     }
     return COMMON_SUCCESS;
}

int CreateRootCA(){
    int ret = COMMON_ERROR;
    Certificate_t* crt = 0;
    EC_KEY* key = NULL;
    const char* sn = "xingyunhulian";
    size_t snlen = strlen(sn);
    const char* filename = "keys/rootCA";
    unsigned char* pub = NULL;
    unsigned char* buffer = NULL;
    size_t blen = 0;
    unsigned char* sig = NULL;
    size_t slen = 0;

    key = CreateSm2KeyPair();
    if (!key) {
        printf("CreateRootCA CreateSm2KeyPair fail\n");
        goto err;
    }
    pub = get_sm2_public_key(key);
    if (!pub) {
        printf("CreateRootCA get_sm2_public_key fail\n");
        goto err;
    }

    crt = (Certificate_t* )calloc(1, sizeof(Certificate_t));
    if (!crt) {
        printf("CreateRootCA calloc crt fail\n");
        goto err;
    }
    crt->signature.present = Signature_PR_signature;
    crt->signature.choice.signature.buf =  (uint8_t* )malloc(32);
    memset(crt->signature.choice.signature.buf, 0, 32);
    crt->signature.choice.signature.size = 32;

    crt->signerInfo = (SignerInfo_t*)CALLOC(1, sizeof(SignerInfo_t));
    crt->signerInfo->present = SignerInfo_PR_self;
    crt->signerInfo->choice.self = 0;

    crt->subjectAttributes.verificationKey = (PublicKey_t*)CALLOC(1, sizeof(PublicKey_t));
    crt->subjectAttributes.verificationKey->present = PublicKey_PR_signKey;
    crt->subjectAttributes.verificationKey->choice.signKey.buf =  (uint8_t* )malloc(32);
    memset(crt->subjectAttributes.verificationKey->choice.signKey.buf, 0, 32);
    memcpy(crt->subjectAttributes.verificationKey->choice.signKey.buf, pub, 32);
    crt->subjectAttributes.verificationKey->choice.signKey.size = 32;

    crt->subjectInfo.subjectName.buf = (uint8_t* )malloc(snlen);
    memset(crt->subjectInfo.subjectName.buf, 0, snlen);
    memcpy(crt->subjectInfo.subjectName.buf, sn, snlen);
    crt->subjectInfo.subjectName.size = snlen;

    crt->subjectInfo.subjectType = SubjectType_rootCa;

    crt->validityRestrictions.present = ValidityRestriction_PR_timeStartAndEnd;
    crt->validityRestrictions.choice.timeStartAndEnd.startValidity = get_diff_time_by_now();
    crt->validityRestrictions.choice.timeStartAndEnd.endValidity = get_diff_time_by_years(10);

    crt->version = CERTIFICATE_VERSION;

    if(COMMON_SUCCESS != CertificateToBuffer(&buffer, &blen, crt)){
        printf("CreateRootCA CertificateToBuffer fail\n");
        goto err;
    }

    if(0 != SignData(key, crt->subjectInfo.subjectName.buf, buffer, blen, &sig, &slen)){
        printf("CreateRootCA SignData fail\n");
        goto err;
    }

    memcpy(crt->signature.choice.signature.buf, sig, 32);
    crt->signature.choice.signature.size = 32;

    if(COMMON_SUCCESS != CertificateToFile("crts/rootCA", crt)){
        printf("CreateRootCA CertificateToFile fail\n");
        goto err;
    }

    if(COMMON_SUCCESS != KeyToFile(filename, key)){
        printf("CreateRootCA KeyToFile fail\n");
        goto err;
    }

    ret = COMMON_SUCCESS;
    err:{
        if (sig) {
            free(sig);
        }
        if (pub) {
            free(pub);
        }
        if (key) {
            EC_KEY_free(key);
        }
        if (crt) {
            ASN_STRUCT_FREE(asn_DEF_Certificate, crt);
        }
    }
    return ret;
}

int CreateSubCA(Certificate_t* rootca, EC_KEY* rootkey, e_SubjectType  type, const unsigned char* filename_crt, const unsigned char* filename_key){
    int ret = COMMON_ERROR;
    Certificate_t* crt = 0;
    EC_KEY* key = NULL;
    const char* sn = SUBJECT_INFO_NAME;
    size_t snlen = strlen(sn);
    unsigned char* pub = NULL;
    unsigned char* buffer = NULL;
    size_t blen = 0;
    unsigned char* hash_buffer = NULL;
    size_t hashlen = 0;
    unsigned char* rootCa_buffer = NULL;
    size_t rootCa_blen = 0;
    unsigned char* sig = NULL;
    size_t slen = 0;

    key = CreateSm2KeyPair();
    if (!key) {
        printf("CreateSubRootCA CreateSm2KeyPair fail\n");
        goto err;
    }
    pub = get_sm2_public_key(key);
    if (!pub) {
        printf("CreateSubRootCA get_sm2_public_key fail\n");
        goto err;
    }

    crt = (Certificate_t* )calloc(1, sizeof(Certificate_t));
    if (!crt) {
        printf("CreateSubRootCA calloc crt fail\n");
        goto err;
    }

    if(CertificateToBuffer(&rootCa_buffer,&rootCa_blen,rootca) != COMMON_SUCCESS){
        printf("CreateSubRootCA CertificateToBuffer fail\n");
        goto err;
    }

    if(Sm3Hash(rootCa_buffer, rootCa_blen, &hash_buffer, &hashlen) != COMMON_SUCCESS){
        printf("CreateSubRootCA Sm3Hash fail\n");
        goto err;
    }

    crt->signature.present = Signature_PR_signature;
    crt->signature.choice.signature.buf =  (uint8_t* )malloc(32);
    memset(crt->signature.choice.signature.buf, 0, 32);
    crt->signature.choice.signature.size = 32;

    crt->signerInfo = (SignerInfo_t*)CALLOC(1, sizeof(SignerInfo_t));
    crt->signerInfo->present = SignerInfo_PR_certificateDigestWithSM3;
    crt->signerInfo->choice.certificateDigestWithSM3.buf = (uint8_t* )malloc(8);
    memset(crt->signerInfo->choice.certificateDigestWithSM3.buf, 0, 8);
    memcpy(crt->signerInfo->choice.certificateDigestWithSM3.buf, hash_buffer+24, 8);
    crt->signerInfo->choice.certificateDigestWithSM3.size = 8;

    crt->subjectAttributes.verificationKey = (PublicKey_t*)CALLOC(1, sizeof(PublicKey_t));
    crt->subjectAttributes.verificationKey->present = PublicKey_PR_signKey;
    crt->subjectAttributes.verificationKey->choice.signKey.buf =  (uint8_t* )malloc(32);
    memset(crt->subjectAttributes.verificationKey->choice.signKey.buf, 0, 32);
    memcpy(crt->subjectAttributes.verificationKey->choice.signKey.buf, pub, 32);
    crt->subjectAttributes.verificationKey->choice.signKey.size = 32;

    crt->subjectInfo.subjectName.buf = (uint8_t* )malloc(snlen);
    memset(crt->subjectInfo.subjectName.buf, 0, snlen);
    memcpy(crt->subjectInfo.subjectName.buf, sn, snlen);
    crt->subjectInfo.subjectName.size = snlen;

    crt->subjectInfo.subjectType = type;

    crt->validityRestrictions.present = ValidityRestriction_PR_timeStartAndEnd;
    crt->validityRestrictions.choice.timeStartAndEnd.startValidity = get_diff_time_by_now();
    crt->validityRestrictions.choice.timeStartAndEnd.endValidity = get_diff_time_by_years(10);

    crt->version = CERTIFICATE_VERSION;

    if(COMMON_SUCCESS != CertificateToBuffer(&buffer, &blen, crt)){
        printf("CreateSubRootCA CertificateToBuffer fail\n");
        goto err;
    }

    if(0 != SignData(rootkey, crt->subjectInfo.subjectName.buf, buffer, blen, &sig, &slen)){
        printf("CreateSubRootCA SignData fail\n");
        goto err;
    }

    memcpy(crt->signature.choice.signature.buf, sig, 32);
    crt->signature.choice.signature.size = 32;

    if(COMMON_SUCCESS != CertificateToFile(filename_crt, crt)){
        printf("CreateSubRootCA CertificateToFile fail\n");
        goto err;
    }

    if(COMMON_SUCCESS != KeyToFile(filename_key, key)){
        printf("CreateSubRootCA KeyToFile fail\n");
        goto err;
    }

//  xer_fprint(stdout, &asn_DEF_Certificate, (void* )crt);
    xer_fprint(stdout, &asn_DEF_SignerInfo, (void* )(crt->signerInfo));
    ret = COMMON_SUCCESS;
    err:{
        if (sig) {
            free(sig);
        }
        if (pub) {
            free(pub);
        }
        if (rootCa_buffer) {
            free(rootCa_buffer);
        }
        if (hash_buffer) {
            free(hash_buffer);
        }
        if (key) {
            EC_KEY_free(key);
        }
        if (crt) {
            ASN_STRUCT_FREE(asn_DEF_Certificate, crt);
        }
    }
    return ret;
}

int CreateCRT(Certificate_t* rootca, EC_KEY* rootkey, e_SubjectType type, 
              const unsigned char* filename_crt, const unsigned char* filename_key,
              unsigned long* end_time, unsigned char** pri_key){
    int ret = COMMON_ERROR;
    Certificate_t* crt = 0;
    EC_KEY* key = NULL;
    const char* sn = SUBJECT_INFO_NAME;
    size_t snlen = strlen(sn);
    unsigned char* pub = NULL;
    unsigned char* pri = NULL;
    unsigned char* buffer = NULL;
    size_t blen = 0;
    unsigned char* hash_buffer = NULL;
    size_t hashlen = 0;
    unsigned char* rootCa_buffer = NULL;
    size_t rootCa_blen = 0;
    unsigned char* sig = NULL;
    size_t slen = 0;
    string scrt((char*)filename_crt);
    string skey((char*)filename_key);
    string s;
    stringstream ss;
    key = CreateSm2KeyPair();
    if (!key) {
        printf("CreateSubRootCA CreateSm2KeyPair fail\n");
        goto err;
    }
    pub = get_sm2_public_key(key);
    if (!pub) {
        printf("CreateSubRootCA get_sm2_public_key fail\n");
        goto err;
    }

    pri = get_sm2_private_key(key);
    if (!pri) {
        printf("CreateSubRootCA get_sm2_private_key fail\n");
        goto err;
    }
    *pri_key = pri;
    crt = (Certificate_t* )calloc(1, sizeof(Certificate_t));
    if (!crt) {
        printf("CreateSubRootCA calloc crt fail\n");
        goto err;
    }

    if(CertificateToBuffer(&rootCa_buffer,&rootCa_blen,rootca) != COMMON_SUCCESS){
        printf("CreateSubRootCA CertificateToBuffer fail\n");
        goto err;
    }

//  cout<<endl;
//  for (int i=0; i<rootCa_blen; i++) {
//      printf("0x%02x ",*(rootCa_buffer + i));
//  }
//  cout<<endl;

    if(Sm3Hash(rootCa_buffer, rootCa_blen, &hash_buffer, &hashlen) != COMMON_SUCCESS){
        printf("CreateSubRootCA Sm3Hash fail\n");
        goto err;
    }

    crt->signature.present = Signature_PR_signature;
    crt->signature.choice.signature.buf =  (uint8_t* )malloc(32);
    memset(crt->signature.choice.signature.buf, 0, 32);
    crt->signature.choice.signature.size = 32;

    crt->signerInfo = (SignerInfo_t*)CALLOC(1, sizeof(SignerInfo_t));
    crt->signerInfo->present = SignerInfo_PR_certificateDigestWithSM3;
    crt->signerInfo->choice.certificateDigestWithSM3.buf = (uint8_t* )malloc(8);
    memset(crt->signerInfo->choice.certificateDigestWithSM3.buf, 0, 8);
    memcpy(crt->signerInfo->choice.certificateDigestWithSM3.buf, hash_buffer+24, 8);
    crt->signerInfo->choice.certificateDigestWithSM3.size = 8;

    crt->subjectAttributes.verificationKey = (PublicKey_t*)CALLOC(1, sizeof(PublicKey_t));
    crt->subjectAttributes.verificationKey->present = PublicKey_PR_signKey;
    crt->subjectAttributes.verificationKey->choice.signKey.buf =  (uint8_t* )malloc(32);
    memset(crt->subjectAttributes.verificationKey->choice.signKey.buf, 0, 32);
    memcpy(crt->subjectAttributes.verificationKey->choice.signKey.buf, pub, 32);
    crt->subjectAttributes.verificationKey->choice.signKey.size = 32;

    crt->subjectInfo.subjectName.buf = (uint8_t* )malloc(snlen);
    memset(crt->subjectInfo.subjectName.buf, 0, snlen);
    memcpy(crt->subjectInfo.subjectName.buf, sn, snlen);
    crt->subjectInfo.subjectName.size = snlen;

    crt->subjectInfo.subjectType = type;

    crt->validityRestrictions.present = ValidityRestriction_PR_timeStartAndEnd;
    crt->validityRestrictions.choice.timeStartAndEnd.startValidity = get_diff_time_by_now();
    crt->validityRestrictions.choice.timeStartAndEnd.endValidity = get_diff_time_by_days(7);

    *end_time = get_time_by_diff(crt->validityRestrictions.choice.timeStartAndEnd.endValidity);
    ss<<*end_time;
    ss>>s;

    crt->version = CERTIFICATE_VERSION;

    if(COMMON_SUCCESS != CertificateToBuffer(&buffer, &blen, crt)){
        printf("CreateSubRootCA CertificateToBuffer fail\n");
        goto err;
    }

    if(0 != SignData(rootkey, crt->subjectInfo.subjectName.buf, buffer, blen, &sig, &slen)){
        printf("CreateSubRootCA SignData fail\n");
        goto err;
    }

    memcpy(crt->signature.choice.signature.buf, sig, 32);
    crt->signature.choice.signature.size = 32;

    scrt += s;
    if(COMMON_SUCCESS != CertificateToFile(scrt.c_str(), crt)){
        printf("CreateSubRootCA CertificateToFile fail\n");
        goto err;
    }

    skey += s;
    if(COMMON_SUCCESS != KeyToFile(skey.c_str(), key)){
        printf("CreateSubRootCA KeyToFile fail\n");
        goto err;
    }
    xer_fprint(stdout, &asn_DEF_SignerInfo, (void* )(crt->signerInfo));
//  xer_fprint(stdout, &asn_DEF_Certificate, (void* )crt);
    cout<<endl;
    ret = COMMON_SUCCESS;

    err:{
        if (sig) {
            free(sig);
        }
        if (pub) {
            free(pub);
        }
        if (rootCa_buffer) {
            free(rootCa_buffer);
        }
        if (hash_buffer) {
            free(hash_buffer);
        }
        if (key) {
            EC_KEY_free(key);
        }
        if (crt) {
            ASN_STRUCT_FREE(asn_DEF_Certificate, crt);
        }
    }
    return ret;
}

int CreateNewECA(Certificate_t* rootca, EC_KEY* rootkey, e_SubjectType  type,  unsigned char* key_crt, size_t* clen){
    int ret = COMMON_ERROR;
    Certificate_t* crt = 0;
    EC_KEY* key = NULL;
    const char* sn = SUBJECT_INFO_NAME;
    size_t snlen = strlen(sn);
    unsigned char* pub = NULL;
    unsigned char* pri = NULL;
    unsigned char* buffer = NULL;
    size_t blen = 0;
    unsigned char* hash_buffer = NULL;
    size_t hashlen = 0;
    unsigned char* rootCa_buffer = NULL;
    size_t rootCa_blen = 0;
    unsigned char* sig = NULL;
    size_t slen = 0;

    key = CreateSm2KeyPair();
    if (!key) {
        printf("CreateSubRootCA CreateSm2KeyPair fail\n");
        goto err;
    }
    pub = get_sm2_public_key(key);
    if (!pub) {
        printf("CreateSubRootCA get_sm2_public_key fail\n");
        goto err;
    }

    pri = get_sm2_private_key(key);
    if (!pri) {
        printf("CreateSubRootCA get_sm2_private_key fail\n");
        goto err;
    }
    printf("pri = \n");
    for (int i = 0 ; i<32; i++) {
        printf("0x%02x ", *(pri+i));
    }
    printf("\n");

    memcpy(key_crt, pri, 32);
    crt = (Certificate_t* )calloc(1, sizeof(Certificate_t));
    if (!crt) {
        printf("CreateSubRootCA calloc crt fail\n");
        goto err;
    }

    if(CertificateToBuffer(&rootCa_buffer,&rootCa_blen,rootca) != COMMON_SUCCESS){
        printf("CreateSubRootCA CertificateToBuffer fail\n");
        goto err;
    }

    if(Sm3Hash(rootCa_buffer, rootCa_blen, &hash_buffer, &hashlen) != COMMON_SUCCESS){
        printf("CreateSubRootCA Sm3Hash fail\n");
        goto err;
    }
//crt -start
    crt->signature.present = Signature_PR_signature;
    crt->signature.choice.signature.buf =  (uint8_t* )malloc(32);
    memset(crt->signature.choice.signature.buf, 0, 32);
    crt->signature.choice.signature.size = 32;

    crt->signerInfo = (SignerInfo_t*)CALLOC(1, sizeof(SignerInfo_t));
    crt->signerInfo->present = SignerInfo_PR_certificateDigestWithSM3;
    crt->signerInfo->choice.certificateDigestWithSM3.buf = (uint8_t* )malloc(8);
    memset(crt->signerInfo->choice.certificateDigestWithSM3.buf, 0, 8);
    memcpy(crt->signerInfo->choice.certificateDigestWithSM3.buf, hash_buffer+24, 8);
    crt->signerInfo->choice.certificateDigestWithSM3.size = 8;

    crt->subjectAttributes.verificationKey = (PublicKey_t*)CALLOC(1, sizeof(PublicKey_t));
    crt->subjectAttributes.verificationKey->present = PublicKey_PR_signKey;
    crt->subjectAttributes.verificationKey->choice.signKey.buf =  (uint8_t* )malloc(32);
    memset(crt->subjectAttributes.verificationKey->choice.signKey.buf, 0, 32);
    memcpy(crt->subjectAttributes.verificationKey->choice.signKey.buf, pub, 32);
    crt->subjectAttributes.verificationKey->choice.signKey.size = 32;

    crt->subjectInfo.subjectName.buf = (uint8_t* )malloc(snlen);
    memset(crt->subjectInfo.subjectName.buf, 0, snlen);
    memcpy(crt->subjectInfo.subjectName.buf, sn, snlen);
    crt->subjectInfo.subjectName.size = snlen;

    crt->subjectInfo.subjectType = type;

    crt->validityRestrictions.present = ValidityRestriction_PR_timeStartAndEnd;
    crt->validityRestrictions.choice.timeStartAndEnd.startValidity = get_diff_time_by_now();
    crt->validityRestrictions.choice.timeStartAndEnd.endValidity = get_diff_time_by_years(1);

    crt->version = CERTIFICATE_VERSION;

    if(COMMON_SUCCESS != CertificateToBuffer(&buffer, &blen, crt)){
        printf("CreateSubRootCA CertificateToBuffer fail\n");
        goto err;
    }

    if(0 != SignData(rootkey, crt->subjectInfo.subjectName.buf, buffer, blen, &sig, &slen)){
        printf("CreateSubRootCA SignData fail\n");
        goto err;
    }
//  free(buffer);

    memcpy(crt->signature.choice.signature.buf, sig, 32);
    crt->signature.choice.signature.size = 32;
//crt -end

    if(COMMON_SUCCESS != CertificateToBuffer(&buffer, &blen, crt)){
        printf("CreateSubRootCA CertificateToBuffer fail\n");
        goto err;
    }
    memcpy(key_crt+32, buffer, blen);
    *clen = blen;
    xer_fprint(stdout, &asn_DEF_SignerInfo, (void* )(crt->signerInfo));
//  xer_fprint(stdout, &asn_DEF_Certificate, (void* )crt);
    cout<<endl;
    ret = COMMON_SUCCESS;

    err:{
        if (sig) {
            free(sig);
        }
        if (pub) {
            free(pub);
        }
        if (rootCa_buffer) {
            free(rootCa_buffer);
        }
        if (hash_buffer) {
            free(hash_buffer);
        }
        if (key) {
            EC_KEY_free(key);
        }
        if (crt) {
            ASN_STRUCT_FREE(asn_DEF_Certificate, crt);
        }
    }
    return ret;
}
int GetCaAndKeyFromFile(const char* filename_crt, const char* filename_key, Certificate_t** crt, EC_KEY** key){
   int ret = COMMON_ERROR;
    FILE* fp_crt = NULL;
    FILE* fp_key = NULL;
    EC_KEY* mkey = NULL;
    Certificate_t* mcrt = NULL;

    fp_crt = fopen(filename_crt, "r+");
    if (!fp_crt) {
        printf("GetRootCaAndKeyFromFile: fopen %s fail\n", filename_crt);
        goto err;
    }
    fp_key = fopen(filename_key, "r+");
    if (!fp_key) {
        printf("GetRootCaAndKeyFromFile: fopen %s fail\n", filename_key);
        goto err;
    }

    mkey = FileToKey(filename_key);
    if (!mkey) {
        printf("GetRootCaAndKeyFromFile: FileToKey fail\n");
        goto err;
    }

    mcrt = FileToCertificate(filename_crt);
    if (!mcrt) {
        printf("GetRootCaAndKeyFromFile: FileToCertificate fail\n");
        goto err;
    }

    *key = mkey;
    *crt = mcrt;

    ret= COMMON_SUCCESS;
    err:{
        fclose(fp_crt);
        fclose(fp_key);
    }
    return ret;
}
int LoadCaAndKeyFromFile(const char* filename_crt, const char* filename_key, Certificate_t** crt, EC_KEY** key, 
                         unsigned char** crt_buff, size_t* crt_buff_len){
    int ret = COMMON_ERROR;
    FILE* fp_crt = NULL;
    FILE* fp_key = NULL;
    EC_KEY* mkey = NULL;
    Certificate_t* mcrt = NULL;
//  unsigned char* crt_buffer = NULL;
//  size_t crt_buffer_len = 0;
    fp_crt = fopen(filename_crt, "r+");
    if (!fp_crt) {
        printf("LoadCaAndKeyFromFile: fopen %s fail\n", filename_crt);
        goto err;
    }
    fp_key = fopen(filename_key, "r+");
    if (!fp_key) {
        printf("LoadCaAndKeyFromFile: fopen %s fail\n", filename_key);
        goto err;
    }

    mkey = FileToKey(filename_key);
    if (!mkey) {
        printf("LoadCaAndKeyFromFile: FileToKey fail\n");
        goto err;
    }

    mcrt = FileToCertificate(filename_crt);
    if (!mcrt) {
        printf("LoadCaAndKeyFromFile: FileToCertificate fail\n");
        goto err;
    }

    if(FileToBuffer(filename_crt, crt_buff, crt_buff_len) != COMMON_SUCCESS){
        printf("LoadCaAndKeyFromFile: FileToBuffer fail\n");
        goto err;
    }

    *key = mkey;
    *crt = mcrt;

    ret= COMMON_SUCCESS;
    err:{
        fclose(fp_crt);
        fclose(fp_key);
    }
    return ret;
}

