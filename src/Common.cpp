/***********************************************
* @addtogroup Nebula
* @{
* @file  : Common.cpp
* @brief :
* @date  : 2019-04-25
***********************************************/
 
//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------
  
#include "Common.h"
#include <iostream>
using namespace std;

EC_KEY* CreateSm2KeyPair(){
    EC_KEY *key = NULL;
    key = EC_KEY_new_by_curve_name(NID_sm2);
    if (!key) {
	printf("CreateSm2KeyPair :EC_KEY_new_by_curve_name(NID_sm2) fail\n");
	return NULL;
    }
    if(0 == EC_KEY_generate_key(key)){
        printf("CreateSm2KeyPair: EC_KEY_generate_key fail\n");
        if (key) {
            EC_KEY_free(key);
        }
        return NULL;
    }
    return key;
}

int SignData(EC_KEY* key, const char* id,  const unsigned char* msg, size_t msg_len, 
             unsigned char** sig, size_t* sig_len){

    *sig = NULL;
    *sig_len = 0;
    if (!key || !id || !msg) {
        return COMMON_NULL_POINT;
    }

    ECDSA_SIG* signature = NULL;
    int ret = COMMON_ERROR;
    int len = 0;
    signature = SM2_do_sign(key, EVP_sm3(), id, msg, msg_len);
    if (!signature) {
        printf("SignData: SM2_do_sign fail\n");
        goto err;
    }
    len = i2d_ECDSA_SIG(signature, sig);
    if (len == 0) {
        printf("SignData: i2d_ECDSA_SIG fail\n");
        goto err;
    }
    *sig_len = len;
    ret = COMMON_SUCCESS;
    err:{
        if (signature) {
            ECDSA_SIG_free(signature);
        }
    }
    return ret;
}

int VerifySignedData(EC_KEY* key, const unsigned char* sig, size_t sig_len, const char* id, 
                     const unsigned char* msg, int msg_len){
    if (!key || !sig || !id || !msg) {
        return COMMON_NULL_POINT;
    }
    ECDSA_SIG *ecdsa_sig = NULL;
    int ret = COMMON_ERROR;
    ecdsa_sig = d2i_ECDSA_SIG(NULL, &sig, sig_len);
    if (!ecdsa_sig) {
        printf("VerifySignedData: d2i_ECDSA_SIG fail\n");
        goto err;
    }

    if (1 != SM2_do_verify(key, EVP_sm3(), ecdsa_sig, id, msg, msg_len)) {
        printf("VerifySignedData: SM2_do_verify fail\n");
        goto err;
    }

    ret = COMMON_SUCCESS;
    err:{
        if (ecdsa_sig) {
            ECDSA_SIG_free(ecdsa_sig);
        }
    }
    return ret;
}

int EncryptData(EC_KEY* key, const unsigned char* msg, size_t msg_len, 
                 unsigned char** ciphertext, size_t* ciphertext_len){

    *ciphertext = NULL;
    *ciphertext_len = 0;
    if (!key || !msg) {
        return COMMON_NULL_POINT;
    }
    size_t len = SM2_ciphertext_size(key, EVP_sm3(), msg_len);
    int ret = COMMON_ERROR;
    unsigned char *c = NULL;
    if (len <= 0) {
        printf("EncryptData: get SM2_ciphertext_size fail\n");
        goto err;
    }
    c = (unsigned char* )calloc(len + 2, sizeof(unsigned char));
    if (!c) {
        printf("EncryptData: malloc ciphertext fail\n");
        goto err;
    }

    if (1 != SM2_encrypt(key, EVP_sm3(), (uint8_t* )msg, msg_len, (uint8_t* )c, ciphertext_len)) {
        printf("EncryptData: SM2_encrypt fail\n");
        free(c);
        goto err;
    }

    *ciphertext = c;
    ret = COMMON_SUCCESS;
    err:{

    }
    return ret;
}

int DecryptData(EC_KEY* key, const unsigned char* ciphertext, size_t ciphertext_len, 
                 unsigned char** plaintext, size_t* plaintext_len){

    *plaintext = NULL;
    *plaintext_len = 0;
    if (!key || !ciphertext) {
        return COMMON_NULL_POINT;
    }

    size_t len = SM2_plaintext_size(key, EVP_sm3(), ciphertext_len);
    int ret = COMMON_ERROR;
    unsigned char *p = NULL;
    if (len <= 0) {
        printf("DecryptData: get SM2_plaintext_size fail\n");
        goto err;
    }
    p = (unsigned char* )calloc(len, sizeof(unsigned char));
    if (!p) {
        printf("DecryptData: malloc plaintext fail\n");
        goto err;
    }
    
    if (1 != SM2_decrypt(key, EVP_sm3(), (uint8_t* )ciphertext, ciphertext_len, (uint8_t* )p, plaintext_len)) {
        printf("DecryptData: SM2_decrypt fail\n");
        free(p);
        goto err;
    }

    *plaintext = p;
    ret = COMMON_SUCCESS;
    err:{

    }
    return ret;
}

int Sm3Hash(unsigned char* msg, size_t msg_len, unsigned char** hash, size_t* hash_len){

    *hash = NULL;
    *hash_len = 0;
    if (!msg) {
        return COMMON_NULL_POINT;
    }

    EVP_MD_CTX *mdctx = NULL;
    unsigned char *dgst = NULL;
    int ret = COMMON_ERROR;
    size_t dgstlen = 0;
    if(!(mdctx = EVP_MD_CTX_create())) {
        printf("Sm3Hash: EVP_MD_CTX_create fail\n");
        goto err;
    }
    if(1 != EVP_DigestInit(mdctx, EVP_sm3())) {
        printf("Sm3Hash: EVP_DigestInit fail\n");
        goto err;
    }
    if(1 != EVP_DigestUpdate(mdctx, (void* )msg, msg_len)) {
        printf("Sm3Hash: EVP_DigestUpdate fail\n");
        goto err;
    }

    dgst = (unsigned char* )calloc(SM3_HASH_LENGTH, sizeof(unsigned char));
    if (!dgst) {
        printf("Sm3Hash: malloc dgst fail\n");
        goto err;
    }
    if (!EVP_DigestFinal(mdctx, dgst, (unsigned int* )&dgstlen)) {
        printf("Sm3Hash: EVP_DigestFinal fail\n");
        free(dgst);
        goto err;
    }

    *hash_len = dgstlen;
    *hash = dgst;
    ret = COMMON_SUCCESS;
    err:{
        if (mdctx) {
            EVP_MD_CTX_free(mdctx);
        }
    }

    return ret;
}

int EncryptDataBySm4Cbc(unsigned char *plaintext, int plaintext_len, unsigned char *key,
unsigned char *iv, unsigned char **ciphertext, int* ciphertext_len){

    *ciphertext = NULL;
    *ciphertext_len = 0;
    if (!plaintext || !key || !iv) {
        return COMMON_NULL_POINT;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *c = NULL;
    int ret = COMMON_ERROR;
    int outlen = 0;
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        printf("EncryptDataBySm4Cbc: EVP_CIPHER_CTX_new fail\n");
        goto err;
    }
    //ecb no need iv
    if(1 != EVP_EncryptInit(ctx, EVP_sm4_cbc(), key, iv)){
        printf("EncryptDataBySm4Cbc: EVP_EncryptInit fail\n");
        goto err;
    }

    c = (unsigned char* )calloc(plaintext_len + 16, sizeof(unsigned char));
    if (!c) {
        printf("EncryptDataBySm4Cbc: malloc ciphertext fail\n");
        goto err;
    }

    if(1 != EVP_EncryptUpdate(ctx, c, &outlen, plaintext, plaintext_len)){
        printf("EncryptDataBySm4Cbc: EVP_EncryptUpdate fail\n");
        free(c);
        goto err;
    }
        
    *ciphertext_len = outlen;

    if(1 != EVP_EncryptFinal(ctx, c + outlen, &outlen)) {
        printf("EncryptDataBySm4Cbc: EVP_EncryptFinal fail\n");
        free(c);
        goto err;
    }

    *ciphertext_len += outlen;
    *ciphertext = c;
    ret = COMMON_SUCCESS;
    err:{
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
    return ret;
}


int EncryptDataBySm4Ecb(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                        unsigned char **ciphertext, int* ciphertext_len){

    *ciphertext = NULL;
    *ciphertext_len = 0;
    if (!plaintext || !key) {
        return COMMON_NULL_POINT;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *c = NULL;
    int outlen = 0;
    int ret = COMMON_ERROR;
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        printf("EncryptDataBySm4Ebc: EVP_CIPHER_CTX_new fail\n");
        goto err;
    }

    if(1 != EVP_EncryptInit(ctx, EVP_sm4_ecb(), key, NULL)){
        printf("EncryptDataBySm4Ebc: EVP_EncryptInit fail\n");
        goto err;
    }

    c = (unsigned char* )calloc(plaintext_len + 16, sizeof(unsigned char));
    if (!c) {
        printf("EncryptDataBySm4Ebc: malloc ciphertext fail\n");
        goto err;
    }

    if(1 != EVP_EncryptUpdate(ctx, c, &outlen, plaintext, plaintext_len)){
        printf("EncryptDataBySm4Ebc: EVP_EncryptUpdate fail\n");
        free(c);
        goto err;
    }
        
    *ciphertext_len = outlen;

    if(1 != EVP_EncryptFinal(ctx, c + outlen, &outlen)) {
        printf("EncryptDataBySm4Ebc: EVP_EncryptFinal fail\n");
        free(c);
        goto err;
    }

    *ciphertext_len += outlen;
    *ciphertext = c;
    ret = COMMON_SUCCESS;
    err:{
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
    return COMMON_SUCCESS;
}

int DecryptDataBySm4Ecb(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, 
                        unsigned char** plaintext, int* plaintext_len){

    *plaintext = NULL;
    *plaintext_len = 0;
    if (!ciphertext || !key) {
        return COMMON_NULL_POINT;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *p = NULL;
    int len = 0;
    int ret = COMMON_ERROR;

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        printf("DecryptDataBySm4Ecb: EVP_CIPHER_CTX_new fail\n");
        goto err;
    }

    if(1 != EVP_DecryptInit(ctx, EVP_sm4_cbc(), key, NULL)){
        printf("DecryptDataBySm4Ecb: EVP_DecryptInit fail\n");
        goto err;
    }

    p = (unsigned char* )calloc(ciphertext_len, sizeof(unsigned char));
    if (!p) {
        printf("DecryptDataBySm4Ecb: malloc plaintext fail\n");
        goto err;
    }

    if(1 != EVP_DecryptUpdate(ctx, p, &len, ciphertext, ciphertext_len)){
        printf("DecryptDataBySm4Ecb: EVP_DecryptUpdate fail\n");
        free(p);
        goto err;
    }

    *plaintext_len = len;

    if(1 != EVP_DecryptFinal(ctx, p + len, &len)) {
        printf("DecryptDataBySm4Ecb: EVP_DecryptFinal fail\n");
        free(p);
        goto err;
    }

    *plaintext_len += len;
    *plaintext = p;
    ret = COMMON_SUCCESS;
    err:{
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
    return ret;
}


int DecryptDataBySm4Cbc(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, 
                       unsigned char* iv, unsigned char** plaintext, int* plaintext_len){

    *plaintext = NULL;
    *plaintext_len = 0;
    if (!ciphertext || !key) {
        return COMMON_NULL_POINT;
    }
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *p = NULL;
    int len = 0;
    int result = COMMON_ERROR;

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        printf("DecryptDataBySm4Cbc: EVP_CIPHER_CTX_new fail\n");
        goto err;
    }
    //ecb no need iv
    if(1 != EVP_DecryptInit(ctx, EVP_sm4_cbc(), key, iv)){
        printf("DecryptDataBySm4Cbc: EVP_DecryptInit fail\n");
        goto err;
    }

    p = (unsigned char* )calloc(ciphertext_len, sizeof(unsigned char));
    if (!p) {
        printf("DecryptDataBySm4Cbc: malloc plaintext fail\n");
        goto err;
    }

    if(1 != EVP_DecryptUpdate(ctx, p, &len, ciphertext, ciphertext_len)){
        printf("DecryptDataBySm4Cbc: EVP_DecryptUpdate fail\n");
        free(p);
        goto err;
    }

    *plaintext_len = len;
    if(1 != EVP_DecryptFinal(ctx, p + len, &len)) {
        printf("DecryptDataBySm4Cbc: EVP_DecryptFinal fail\n");
        free(p);
        goto err;
    }

    *plaintext_len += len;
    *plaintext = p;
    result = COMMON_SUCCESS;
    err:{
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
    return result;
}


int DeriveKey(EC_KEY* mkey, EC_KEY* okey, unsigned char** key, size_t* keylen){
    if (!mkey || !okey) {
        return COMMON_NULL_POINT;
    }
    *key = NULL;
    *keylen = 0;
    int result = COMMON_ERROR;
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY* peerkey = EVP_PKEY_new();
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char* k = NULL;

    if(!EVP_PKEY_set1_EC_KEY(pkey, mkey)){
        printf("DeriveKey: EVP_PKEY_set1_EC_KEY mkey fail\n");
        goto err;
    }
    if(!EVP_PKEY_set1_EC_KEY(peerkey, okey)){
        printf("DeriveKey: EVP_PKEY_set1_EC_KEY okey fail\n");
        goto err;
    }
  
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx){
        printf("DeriveKey: EVP_PKEY_CTX_new fail\n");
        goto err;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0){
        printf("DeriveKey: EVP_PKEY_derive_init fail\n");
        goto err;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0){
        printf("DeriveKey: EVP_PKEY_derive_set_peer fail\n");
        goto err;
    }

    if (EVP_PKEY_derive(ctx, NULL, keylen) <= 0){
        printf("DeriveKey: EVP_PKEY_derive fail\n");
        goto err;
    }

    k = (unsigned char* )calloc(*keylen, sizeof(unsigned char));
    if (!k) {
        printf("DeriveKey: malloc key fail\n");
        goto err;
    }
    if (EVP_PKEY_derive(ctx, k, keylen) <= 0) {
        printf("DeriveKey: EVP_PKEY_derive fail\n");
        goto err;
    }

    result = COMMON_SUCCESS;
    *key = k;
    err:{
        if (pkey) {
            EVP_PKEY_free(pkey);
        }
        if (peerkey) {
            EVP_PKEY_free(peerkey);
        }
        if (ctx) {
            EVP_PKEY_CTX_free(ctx );
        }
    }
    return result;
}

int KeyToFile(const char* filename, EC_KEY* key){

    int ret = COMMON_ERROR;
    unsigned char* pub = NULL;
    unsigned char* pri = NULL;
    unsigned char* buff_key = NULL;
    FILE* fp = NULL;
    fp = fopen(filename, "w+");
    if (!fp) {
        printf("KeyToFile fopen %s failed\n", filename);
        goto err;
    }

    pub = get_sm2_public_key(key);
    if (!pub) {
        printf("KeyToFile get_sm2_public_key fail\n");
        goto err;
    }

    pri = get_sm2_private_key(key);
    if (!pri) {
        printf("KeyToFile get_sm2_private_key fail\n");
        goto err;
    }

    buff_key = (unsigned char*)calloc(SM2_PRIVATE_KEY_LENGTH + SM2_PUBLIC_KEY_LENGTH, sizeof(unsigned char));
    if (!buff_key) {
        printf("KeyToFile calloc buff_key fail\n");
        goto err;
    }
    memcpy(buff_key, pri, SM2_PRIVATE_KEY_LENGTH);
    memcpy(buff_key +SM2_PRIVATE_KEY_LENGTH, pub, SM2_PUBLIC_KEY_LENGTH);
    for (int i = 0; i < SM2_PRIVATE_KEY_LENGTH + SM2_PUBLIC_KEY_LENGTH; i++) {
        fprintf(fp ,"%c", *(buff_key+i));
//      printf("0x%02x ", *(buff_key+i));
    }

    ret = COMMON_SUCCESS;
    err:{
        if (pub) {
            free(pub);
        }
        if (pri) {
            free(pri);
        }
        if (buff_key) {
            free(buff_key);
        }
        if (fp) {
            fclose(fp);
        }
    }
    
    return ret;
}

EC_KEY* FileToKey(const char* filename){
    if (!filename) {
        return NULL;
    }

    FILE* fp = fopen(filename, "r");
    if (!fp) {
        printf("FileToKey: Cannot open file: %s\n", filename);
        return NULL;
    }

    unsigned char *buffer = (unsigned char* )calloc(SM2_PRIVATE_KEY_LENGTH+ SM2_PUBLIC_KEY_LENGTH, sizeof(unsigned char));
    size_t blen = 0;
    for (int i = 0; true; i++, blen++) {
        if (1 != fread(buffer + i, sizeof(unsigned char), 1, fp)) break;
    }

    unsigned char *pri = (unsigned char* )calloc(SM2_PRIVATE_KEY_LENGTH, sizeof(unsigned char));
    memcpy(pri, buffer, SM2_PRIVATE_KEY_LENGTH);
    unsigned char *pub = (unsigned char* )calloc(SM2_PUBLIC_KEY_LENGTH, sizeof(unsigned char));  
    memcpy(pub, buffer + SM2_PRIVATE_KEY_LENGTH, SM2_PUBLIC_KEY_LENGTH);

    free(buffer);

    EC_GROUP *eg = NULL;
    BIGNUM* mpri = NULL;
    BIGNUM* x = NULL;
    BIGNUM* y = NULL;
    EC_POINT* mpub = NULL;
    EC_KEY* key = NULL;
    key = CreateSm2KeyPair();
    if (!key) {
        printf("FileToKey: CreateSm2KeyPair fail\n");
        goto err;
    }

    eg = EC_KEY_get0_group(key);
    if (!eg) {
        printf("FileToKey: EC_KEY_get0_group fail\n");
        goto err;
    }
    mpub = EC_KEY_get0_public_key(key);
    if (!mpub) {
        printf("FileToKey: EC_KEY_get0_public_key fail\n");
        goto err;
    }
    mpri = BN_bin2bn(pri, SM2_PRIVATE_KEY_LENGTH, NULL);
    if (!mpri) {
        printf("FileToKey: BN_bin2bn mpri fail\n");
        goto err;
    }
    x = BN_bin2bn(pub+1, SM2_PRIVATE_KEY_LENGTH, NULL);
    if (!x) {
        printf("FileToKey: BN_bin2bn x fail\n");
        goto err;
    }
    y = BN_bin2bn(pub+1+SM2_PRIVATE_KEY_LENGTH, SM2_PRIVATE_KEY_LENGTH, NULL);
    if (!y) {
        printf("FileToKey: BN_bin2bn y fail\n");
        goto err;
    }

    if(1 != EC_KEY_set_private_key(key, mpri)){
        printf("FileToKey: EC_KEY_set_private_key fail\n");
        goto err;
    }

    if(1 != EC_POINT_set_affine_coordinates_GFp(eg, mpub, x, y, NULL)){
        printf("FileToKey: EC_POINT_set_affine_coordinates_GFp fail\n");
        goto err;
    }

    err:{
        /*
        if (pri) {
            free(pri);
        }
        if (pub) {
            free(pri);
        }
        */
    }
    return key;
}

int FileToBuffer(const char* filename, unsigned char** buff, size_t* blen){
    if (!filename) {
        return COMMON_NULL_POINT;
    }
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        printf("FileToBuffer: Cannot open file: %s\n", filename);
        return NULL;
    }
    unsigned char *buffer = (unsigned char* )calloc(1024, sizeof(unsigned char));
    size_t len = 0;
    for (int i = 0; true; i++, len++) {
        if (1 != fread(buffer + i, sizeof(unsigned char), 1, fp)) break;
    }
    *blen = len;
    *buff = buffer;
    return COMMON_SUCCESS;
}

unsigned char* get_sm2_private_key(const EC_KEY* key){
    if (!key) {
        return NULL;
    }
    unsigned char *pri = NULL;
    pri = (unsigned char* )calloc(SM2_PRIVATE_KEY_LENGTH, sizeof(unsigned char));
    if (!pri) {
        printf("get_sm2_private_key malloc pri_key failed\n");
        goto err;
    }

    if (!BN_bn2bin(EC_KEY_get0_private_key(key), pri)) {
        printf("get_sm2_private_key BN_bn2bin failed\n");
        free(pri);
        pri = NULL;
        goto err;
    }
    err:{
        
    }
    return pri;
}

unsigned char* get_sm2_public_key(const EC_KEY* key){
    if (!key) {
        return NULL;
    }

    EC_GROUP *eg = NULL;
    EC_POINT *ep = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    unsigned char *pub = NULL;

    ep = EC_KEY_get0_public_key(key);
    if (!ep) {
        printf("get_sm2_public_key EC_KEY_get0_public_key failed\n");
        goto err;
    }

    eg = EC_KEY_get0_group(key);
    if (!eg) {
        printf("get_sm2_public_key EC_KEY_get0_group failed\n");
        goto err;
    }

    x = BN_new();
    if (!x) {
        printf("get_sm2_public_key BN_new x failed\n");
        goto err;
    }

    y = BN_new();
    if (!y) {
        printf("get_sm2_public_key BN_new y failed\n");
        goto err;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(eg, ep, x, y, NULL)) {
        printf("get_sm2_public_key EC_POINT_get_affine_coordinates_GFp failed\n");
        goto err;
    }

    pub = (unsigned char* )calloc(SM2_PUBLIC_KEY_LENGTH, sizeof(unsigned char));
    if (!pub) {
        printf("get_sm2_public_key malloc pub_key failed\n");
        goto err;
    }
    memset(pub, 0x04, 1);

    if (!BN_bn2bin(x, pub + 1)) {
        printf("get_sm2_public_key BN_bn2bin failed\n");
        free(pub);
        pub = NULL;
        goto err;
    }

    if (!BN_bn2bin(y, pub + 1 + 32)) {
        printf("get_sm2_public_key BN_bn2bin failed\n");
        free(pub);
        pub = NULL;
        goto err;
    }

    err:{
        if(x){
            BN_free(x);
        }
        if(y){
            BN_free(y);
        }
    }

    return pub;
}

unsigned long get_diff_time_by_now(){
    struct tm time_2004;
    time_2004.tm_sec = 0;
    time_2004.tm_min = 0;
    time_2004.tm_hour = 0;
    time_2004.tm_mday = 1;
    time_2004.tm_mon = 1;
    time_2004.tm_year = 104;
    time_t mt_2004 = mktime(&time_2004);
    time_t mt_now = time(0);
    return (unsigned long)(mt_now - mt_2004);
}

unsigned long get_diff_time_by_days(int day){
    struct tm time_2004;
    time_2004.tm_sec = 0;
    time_2004.tm_min = 0;
    time_2004.tm_hour = 0;
    time_2004.tm_mday = 1;
    time_2004.tm_mon = 1;
    time_2004.tm_year = 104;
    time_t mt_2004 = mktime(&time_2004);

    struct tm* time_day = NULL;
    time_t mt_now = time(0);
    time_t mt_day;
    time_day = gmtime(&mt_now);
    time_day->tm_mday += day;

    mt_day = mktime(time_day);

    return (unsigned long)(mt_day - mt_2004);
}

unsigned long get_time_now(){
    return (unsigned long)time(0);
}

unsigned long get_diff_time_by_years(int year){
    struct tm time_2004;
    time_2004.tm_sec = 0;
    time_2004.tm_min = 0;
    time_2004.tm_hour = 0;
    time_2004.tm_mday = 1;
    time_2004.tm_mon = 1;
    time_2004.tm_year = 104;
    time_t mt_2004 = mktime(&time_2004);

    struct tm* time_year = NULL;
    time_t mt_now = time(0);
    time_t mt_year;
    time_year = gmtime(&mt_now);
    time_year->tm_year += year;

    mt_year = mktime(time_year);
    return (unsigned long)(mt_year - mt_2004);
}

unsigned long get_time_by_diff(unsigned long diff){
    struct tm time_2004;
    time_2004.tm_sec = 0;
    time_2004.tm_min = 0;
    time_2004.tm_hour = 0;
    time_2004.tm_mday = 1;
    time_2004.tm_mon = 1;
    time_2004.tm_year = 104;
    time_t mt_2004 = mktime(&time_2004);
    return ((unsigned long)mt_2004 + diff);
}

int CertificateSign(EC_KEY* key, Certificate_t* crt){
    int ret = COMMON_ERROR;
    unsigned char* sig = NULL;
    size_t slen = 0;
    if (!key || !crt) {
        return COMMON_NULL_POINT;
    }

    ECDSA_SIG* signature = NULL;
    int mlen = 0;
    unsigned char *msg = NULL;

    if(CertificateToBuffer(&msg, &mlen, crt) != COMMON_SUCCESS){
        printf("CertificateSign: CertificateToBuffer fail\n");
        goto err;
    }

    signature = SM2_do_sign(key, EVP_sm3(), crt->subjectInfo.subjectName.buf, msg, mlen);
    if (!signature) {
        printf("CertificateSign: SM2_do_sign fail\n");
        goto err;
    }
    slen = i2d_ECDSA_SIG(signature, &sig);
    if (slen == 0) {
        printf("CertificateSign: i2d_ECDSA_SIG fail\n");
        goto err;
    }

    crt->signature.present = Signature_PR_signature;
    crt->signature.choice.signature.buf = (uint8_t* )malloc(32);
    memcpy(crt->signature.choice.signature.buf, sig, 32);
    crt->signature.choice.signature.size = 32;

    ret = COMMON_SUCCESS;
    err:{
        if (signature) {
            ECDSA_SIG_free(signature);
        }
    }
    return ret;
}

int CertificateVerify(EC_KEY* key, Certificate_t* crt){
    int ret = COMMON_ERROR;
    if (!key || !crt) {
        return ret;
    }
    unsigned char* msg = NULL;
    size_t mlen = 0;

    unsigned char* sig = (unsigned char*)calloc(crt->signature.choice.signature.size, sizeof(unsigned char));
    if (!sig) {
        printf("CertificateVerify: calloc sig fail\n");
        goto err;
    }
    memcpy(sig, crt->signature.choice.signature.buf, crt->signature.choice.signature.size);
    memset(crt->signature.choice.signature.buf, 0, 32);

    if(CertificateToBuffer(&msg, &mlen, crt) != COMMON_SUCCESS){
        printf("CertificateVerify: CertificateToBuffer fail\n");
        goto err;
    }

    if (VerifySignedData(key, sig, crt->signature.choice.signature.size, crt->subjectInfo.subjectName.buf, msg, mlen)
        != COMMON_SUCCESS) {
        printf("CertificateVerify: VerifySignedData fail\n");
        goto err;
    }

    ret = COMMON_SUCCESS;
    memcpy(crt->signature.choice.signature.buf, sig, 32);

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

int CrlSign(EC_KEY* key, Crl_t* crl){
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
                                              
    crl->signature.present = Signature_PR_signature;
    crl->signature.choice.signature.buf = (uint8_t* )malloc(32);
    memcpy(crl->signature.choice.signature.buf, sig, 32);
    crl->signature.choice.signature.size = 32;

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


int CreateCRL(EC_KEY* key, unsigned char* subrootca_hash, unsigned char* cca_hash, unsigned char* hashid10, 
              unsigned long crl_serial_number, unsigned long crt_start_time,  unsigned long* sign_time){
    int ret = COMMON_ERROR;
    unsigned char* sig = NULL;
    size_t slen = 0;
    unsigned long stime = 0;
    string name(CRL_FILENAME);
    string stmp;
    stringstream ss;
    Crl_t *crl = NULL;
    crl = (Crl_t*)CALLOC(1, sizeof(Crl_t));
    if (!crl) {
        printf("CreateCRL: calloc() crl failed\n");
        goto err;
    }
    crl->version = CRL_VERSION;

    crl->signerInfo.present = SignerInfo_PR_certificateDigestWithSM3;
    crl->signerInfo.choice.certificateDigestWithSM3.buf = (uint8_t* )malloc(8);
    memcpy(crl->signerInfo.choice.certificateDigestWithSM3.buf, subrootca_hash, 8);
    crl->signerInfo.choice.certificateDigestWithSM3.size = 8;

    crl->unsignedCrl.caId.buf = (uint8_t* )malloc(8);
    memcpy(crl->unsignedCrl.caId.buf, cca_hash, 8);
    crl->unsignedCrl.caId.size = 8;

    crl->unsignedCrl.crlSerial = crl_serial_number;

    crl->unsignedCrl.startPeriod = crt_start_time;
    stime = get_diff_time_by_now();
    crl->unsignedCrl.issueDate = stime;
    ss<<get_time_by_diff(stime);
    ss>>stmp;
    crl->unsignedCrl.nextCrl = stime;

    crl->unsignedCrl.type.present = CrlType_PR_idOnly;
    crl->unsignedCrl.type.choice.idOnly.buf =  (uint8_t* )malloc(10);
    memcpy(crl->unsignedCrl.type.choice.idOnly.buf, hashid10, 10);
    crl->unsignedCrl.type.choice.idOnly.size = 10;

    if(CrlSign(key, crl) != COMMON_SUCCESS){
        printf("CreateCRL: VerifySignedData fail\n");
        goto err;
    }

    name+=stmp;
    if (CrlToFile(name.c_str(), crl)) {
        printf("CreateCRL: CrlToFile fail\n");
        goto err;
    }
    *sign_time = stime;
    ret = COMMON_SUCCESS;
    err:{
        if (sig) {
            free(sig);
        }
        if (crl) {
            ASN_STRUCT_FREE(asn_DEF_Crl, crl);
        }
    }
    return ret;
}


