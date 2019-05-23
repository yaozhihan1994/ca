
/***********************************************
* @addtogroup Nebula
* @{
* @file  : CertOp.cpp
* @brief :
* @date  : 2019-05-13
***********************************************/

//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------

#include "CertOp.h"

s_CaInfo g_rootca;
s_CaInfo g_subrootca;
s_CaInfo g_eca;
s_CaInfo g_pca;
s_CaInfo g_rca;
s_CaInfo g_cca;

CertOp::CertOp(){
}

CertOp::~CertOp(){
}


int CertOp::uper_callback(const void *buffer, size_t size, void *key){
    return 0;
}


EC_KEY* CertOp::CreateSm2KeyPair(){
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

int CertOp::SignData(EC_KEY* key, const unsigned char* msg, size_t msg_len, unsigned char** sig, size_t* sig_len){
    if (!key || !msg) {
        return COMMON_INVALID_PARAMS;
    }

    int ret = COMMON_ERROR;
    const char* id = SM2_USER_ID;
    ECDSA_SIG* signature = NULL;
    const BIGNUM* r = NULL;
    const BIGNUM* s = NULL;
    unsigned char cr[32]={};
    unsigned char cs[32]={};
    unsigned char* buffer = NULL;
    int slen = 0;
    
    signature = SM2_do_sign(key, EVP_sm3(), id, msg, msg_len);
    if (!signature) {
        printf("SignData: SM2_do_sign fail\n");
        goto err;
    }

    ECDSA_SIG_get0(signature, &r, &s);
    if (!r || !s) {
        printf("SignData: ECDSA_SIG_get0 fail\n");
        goto err;
    }

    if (!BN_bn2bin(r, cr)) {
        printf("SignData BN_bn2bin failed\n");
        goto err;
    }

    if (!BN_bn2bin(s, cs)) {
        printf("SignData BN_bn2bin failed\n");
        goto err;
    }

    buffer = (unsigned char* )malloc(64);
    if (!buffer) {
        printf("SignData malloc buffer failed\n");
        goto err;
    }

    memcpy(buffer, cr, 32);
    memcpy(buffer+32, cs, 32);

    *sig = buffer;
    *sig_len = 64;
//  slen = i2d_ECDSA_SIG(signature, sig);
//  if (slen == 0) {
//      printf("SignData: i2d_ECDSA_SIG fail\n");
//      goto err;
//  }
//
//  *sig_len = slen;
    ret = COMMON_SUCCESS;
    err:{
        if (signature) {
            ECDSA_SIG_free(signature);
        }
    }
    return ret;
}

int CertOp::VerifySignedData(EC_KEY* key, const unsigned char* sig, size_t sig_len, const unsigned char* msg, int msg_len){
    if (!key || !sig || !msg) {
        return COMMON_INVALID_PARAMS;
    }
    int ret = COMMON_ERROR;
    ECDSA_SIG *ecdsa_sig = NULL;

    unsigned char cr[32];
    memcpy(cr, sig, 32);
    unsigned char cs[32];
    memcpy(cs, sig+32, 32);
    const char* id = SM2_USER_ID;
    BIGNUM* r;
    BIGNUM* s;

    ecdsa_sig = ECDSA_SIG_new();
    if (!ecdsa_sig) {
        printf("VerifySignedData: ECDSA_SIG_new fail\n");
        goto err;
    }

    r = BN_bin2bn(cr, 32, NULL);
    if (!r) {
        printf("VerifySignedData: BN_bin2bn r fail\n");
        goto err;
    }

    s = BN_bin2bn(cs, 32, NULL);
    if (!s) {
        printf("VerifySignedData: BN_bin2bn s fail\n");
        goto err;
    }

    ECDSA_SIG_set0(ecdsa_sig, r, s);
    if (!ecdsa_sig) {
        printf("VerifySignedData: ECDSA_SIG_set0 fail\n");
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

int CertOp::EncryptData(EC_KEY* key, const unsigned char* msg, size_t msg_len, unsigned char** ciphertext, size_t* ciphertext_len){
    if (!key || !msg) {
        return COMMON_INVALID_PARAMS;
    }

    int ret = COMMON_ERROR;
    unsigned char *c = NULL;
    size_t len = 0;

    len = SM2_ciphertext_size(key, EVP_sm3(), msg_len);
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

int CertOp::DecryptData(EC_KEY* key, const unsigned char* ciphertext, size_t ciphertext_len, unsigned char** plaintext, size_t* plaintext_len){
    if (!key || !ciphertext) {
        return COMMON_INVALID_PARAMS;
    }

    int ret = COMMON_ERROR;
    unsigned char *p = NULL;
    size_t len = 0;

    len = SM2_plaintext_size(key, EVP_sm3(), ciphertext_len);
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

int CertOp::Sm3Hash(unsigned char* msg, size_t msg_len, unsigned char** hash, size_t* hash_len){
    if (!msg) {
        return COMMON_INVALID_PARAMS;
    }

    int ret = COMMON_ERROR;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char *dgst = NULL;
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
        printf("Sm3Hash: calloc dgst fail\n");
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

int CertOp::EncryptDataBySm4(SymmetricAlgorithm type, unsigned char *plaintext, int plaintext_len, unsigned char *key,
                                             unsigned char *iv, unsigned char **ciphertext, int* ciphertext_len){

    if (!plaintext || !key || !iv) {
        return COMMON_INVALID_PARAMS;
    }

    int ret = COMMON_ERROR;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *c = NULL;
    int outlen = 0;
    const EVP_CIPHER* cipher = NULL;

    switch (type) {
        case SymmetricAlgorithm_sgdsm4cbc:{
            cipher = EVP_sm4_cbc();
            break;
        }
        case SymmetricAlgorithm_sgdsm4ecb:{
            cipher = EVP_sm4_ecb();
            iv = NULL;
            break;
        }
        case SymmetricAlgorithm_sgdsm4cfb:{

            break;
        }
        case SymmetricAlgorithm_sgdsm4ofb:{

            break;
        }
        default:{
            printf("EncryptDataBySm4: unknow sm4 type\n");
            break;
        }
    }

    if (cipher == NULL) {
        printf("EncryptDataBySm4: fail\n");
        return ret;
    }

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        printf("EncryptDataBySm4Cbc: EVP_CIPHER_CTX_new fail\n");
        goto err;
    }
 
    if(1 != EVP_EncryptInit(ctx, cipher, key, iv)){
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

int CertOp::DecryptDataBySm4(SymmetricAlgorithm type, unsigned char *ciphertext, int ciphertext_len, unsigned char* key, 
                                              unsigned char* iv, unsigned char** plaintext, int* plaintext_len){

    if (!ciphertext || !key) {
        return COMMON_INVALID_PARAMS;
    }

    int ret = COMMON_ERROR;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *p = NULL;
    int len = 0;
    const EVP_CIPHER* cipher = NULL;

    switch (type) {
        case SymmetricAlgorithm_sgdsm4cbc:{
            cipher = EVP_sm4_cbc();
            break;
        }
        case SymmetricAlgorithm_sgdsm4ecb:{
            cipher = EVP_sm4_ecb();
            iv = NULL;
            break;
        }
        case SymmetricAlgorithm_sgdsm4cfb:{

            break;
        }
        case SymmetricAlgorithm_sgdsm4ofb:{

            break;
        }
        default:{
            printf("EncryptDataBySm4: unknow sm4 type\n");
            break;
        }
    }

    if (cipher == NULL) {
        printf("EncryptDataBySm4: fail\n");
        return ret;
    }

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        printf("DecryptDataBySm4Cbc: EVP_CIPHER_CTX_new fail\n");
        goto err;
    }

    if(1 != EVP_DecryptInit(ctx, cipher, key, iv)){
        printf("DecryptDataBySm4Cbc: EVP_DecryptInit fail\n");
        goto err;
    }

    p = (unsigned char* )calloc(ciphertext_len, sizeof(unsigned char));
    if (!p) {
        printf("DecryptDataBySm4Cbc: calloc plaintext fail\n");
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
    ret = COMMON_SUCCESS;
    err:{
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
    return ret;
}

int CertOp::DeriveKey(EC_KEY* mkey, EC_KEY* okey, unsigned char** key, size_t* keylen){
    if (!mkey || !okey) {
        return COMMON_INVALID_PARAMS;
    }

    int ret = COMMON_ERROR;
    EVP_PKEY* pmkey = NULL;
    EVP_PKEY* pokey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char* k = NULL;

    pmkey = EVP_PKEY_new();
    if(!pmkey){
        printf("DeriveKey: EVP_PKEY_new pmkey fail\n");
        goto err;
    }

    pokey = EVP_PKEY_new();
    if(!pokey){
        printf("DeriveKey: EVP_PKEY_new pokey fail\n");
        goto err;
    }

    if(!EVP_PKEY_set1_EC_KEY(pmkey, mkey)){
        printf("DeriveKey: EVP_PKEY_set1_EC_KEY mkey fail\n");
        goto err;
    }
    if(!EVP_PKEY_set1_EC_KEY(pokey, okey)){
        printf("DeriveKey: EVP_PKEY_set1_EC_KEY okey fail\n");
        goto err;
    }
  
    ctx = EVP_PKEY_CTX_new(pmkey, NULL);
    if (!ctx){
        printf("DeriveKey: EVP_PKEY_CTX_new fail\n");
        goto err;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0){
        printf("DeriveKey: EVP_PKEY_derive_init fail\n");
        goto err;
    }

    if (EVP_PKEY_derive_set_peer(ctx, pokey) <= 0){
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

    ret = COMMON_SUCCESS;
    *key = k;
    err:{
        if (pmkey) {
            EVP_PKEY_free(pmkey);
        }
        if (pokey) {
            EVP_PKEY_free(pokey);
        }
        if (ctx) {
            EVP_PKEY_CTX_free(ctx );
        }
    }
    return ret;
}

unsigned char* CertOp::get_sm2_public_key(const EC_KEY* key){
    if (!key) {
        return NULL;
    }

    const EC_GROUP *eg = NULL;
    const EC_POINT *ep = NULL;
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

    pub = (unsigned char* )calloc(PUBLIC_KEY_LENGTH, sizeof(unsigned char));
    if (!pub) {
        printf("get_sm2_public_key calloc pub_key failed\n");
        goto err;
    }

    if (!BN_bn2bin(x, pub)) {
        printf("get_sm2_public_key BN_bn2bin failed\n");
        free(pub);
        pub = NULL;
        goto err;
    }

    if (!BN_bn2bin(y, pub+ 32)) {
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

unsigned char* CertOp::get_sm2_private_key(const EC_KEY* key){
    if (!key) {
        return NULL;
    }

    unsigned char *pri = NULL;
    pri = (unsigned char* )calloc(PRIVATE_KEY_LENGTH, sizeof(unsigned char));
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

unsigned long CertOp::get_difftime_by_now(){
    return (unsigned long)(time(0) - get_difftime_2004());
}

unsigned long CertOp::get_difftime_2004(){
    struct tm time_2004;
    time_2004.tm_sec = 0;
    time_2004.tm_min = 0;
    time_2004.tm_hour = 0;
    time_2004.tm_mday = 1;
    time_2004.tm_mon = 0;
    time_2004.tm_year = 104;
    time_t time_diff = mktime(&time_2004);
    return (unsigned long)(time_diff);
}

unsigned long CertOp::get_difftime_by_days(int days){
    struct tm* time_day = NULL;
    time_t mt_now = time(0);
    time_t mt_day;
    time_day = localtime(&mt_now);
    time_day->tm_mday += days;
    mt_day = mktime(time_day);
    return (unsigned long)(mt_day - get_difftime_2004());
}

unsigned long CertOp::get_difftime_by_years(int years){
    struct tm* time_year = NULL;
    time_t mt_now = time(0);
    time_t mt_year;
    time_year = localtime(&mt_now);
    time_year->tm_year += years;
    mt_year = mktime(time_year);
    return (unsigned long)(mt_year - get_difftime_2004());
}

unsigned long CertOp::get_time_now(){
    return (unsigned long)time(0);
}

int CertOp::get_hour_now(){
    time_t t = get_time_now();
    struct tm *tm = localtime(&t);
    return tm->tm_hour;
}

unsigned long CertOp::get_time_by_diff(unsigned long diff){
    return diff + get_difftime_2004();
}

int CertOp::FileToBuffer(const char* filename, unsigned char** buff, size_t* blen){
    if (!filename) {
        return COMMON_INVALID_PARAMS;
    }

    FILE* fp = fopen(filename, "r");
    if (!fp) {
        printf("FileToBuffer: Cannot open file: %s\n", filename);
        return COMMON_ERROR;
    }
    unsigned char *buffer = (unsigned char* )calloc(1024, sizeof(unsigned char));
    size_t len = 0;
    for (int i = 0; i<1024; i++, len++) {
        if (1 != fread(buffer + i, sizeof(unsigned char), 1, fp)) break;
    }
    *blen = len;
    *buff = buffer;
    fclose(fp);
    return COMMON_SUCCESS;
}

int CertOp::BufferToFile(const char* filename, unsigned char* buff, size_t blen){
    if (!filename) {
        return COMMON_INVALID_PARAMS;
    }
    FILE* fp = fopen(filename, "w+");
    if (!fp) {
        printf("BufferToFile: Cannot open file: %s\n", filename);
        return COMMON_ERROR;
    }
    for (int i = 0; i < blen; i++) {
        fprintf(fp ,"%c", *(buff+i));
    }
    fclose(fp);
    return COMMON_SUCCESS;
}

//pri+pub
int CertOp::KeyToFile(const char* filename, EC_KEY* key){
    if (!filename || !key) {
        return COMMON_INVALID_PARAMS;
    }
    int ret = COMMON_ERROR;
    unsigned char* pub = NULL;
    unsigned char* pri = NULL;
    unsigned char* buff_key = NULL;
    size_t buff_key_length = 32+64;
    pub = CertOp::get_sm2_public_key(key);
    if (!pub) {
        printf("KeyToFile get_sm2_public_key fail\n");
        goto err;
    }

    pri = CertOp::get_sm2_private_key(key);
    if (!pri) {
        printf("KeyToFile get_sm2_private_key fail\n");
        goto err;
    }

    buff_key = (unsigned char*)calloc(buff_key_length, sizeof(unsigned char));
    if (!buff_key) {
        printf("KeyToFile calloc buff_key fail\n");
        goto err;
    }
    memcpy(buff_key, pri, 32);
    memcpy(buff_key +32, pub, 64);

    if (CertOp::BufferToFile(filename, buff_key, buff_key_length) != COMMON_SUCCESS) {
        printf("KeyToFile BufferToFile fail\n");
        goto err;
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
    }
    return ret;
}

EC_KEY* CertOp::FileToKey(const char* filename){
    if (!filename) {
        return NULL;
    }

    unsigned char* buffer = NULL;
    size_t blen = 0;
    const EC_GROUP *eg = NULL;
    BIGNUM* mpri = NULL;
    const BIGNUM* x = NULL;
    const BIGNUM* y = NULL;
    EC_POINT* mpub = NULL;
    EC_KEY* key = NULL;

    if(CertOp::FileToBuffer(filename, &buffer, &blen) != COMMON_SUCCESS){
        printf("FileToKey FileToBuffer fail\n");
        if (buffer) {
            free(buffer);
        }
        return NULL;
    }

    unsigned char pri[32];
    memcpy(pri, buffer, 32);
    unsigned char pub[64] = {};
    memcpy(pub, buffer + 32, 64);

    free(buffer);

    key = CertOp::CreateSm2KeyPair();
    if (!key) {
        printf("FileToKey: CreateSm2KeyPair fail\n");
        return NULL;
    }

    eg = EC_KEY_get0_group(key);
    if (!eg) {
        printf("FileToKey: EC_KEY_get0_group fail\n");
        return NULL;
    }
    mpub = const_cast<EC_POINT*>(EC_KEY_get0_public_key(key));
    if (!mpub) {
        printf("FileToKey: EC_KEY_get0_public_key fail\n");
        return NULL;
    }
    mpri = BN_bin2bn(pri, 32, NULL);
    if (!mpri) {
        printf("FileToKey: BN_bin2bn mpri fail\n");
        return NULL;
    }
    x = BN_bin2bn(pub, 32, NULL);
    if (!x) {
        printf("FileToKey: BN_bin2bn x fail\n");
        return NULL;
    }
    y = BN_bin2bn(pub+32, 32, NULL);
    if (!y) {
        printf("FileToKey: BN_bin2bn y fail\n");
        return NULL;
    }

    if(1 != EC_KEY_set_private_key(key, mpri)){
        printf("FileToKey: EC_KEY_set_private_key fail\n");
        return NULL;
    }

    if(1 != EC_POINT_set_affine_coordinates_GFp(eg, mpub, x, y, NULL)){
        printf("FileToKey: EC_POINT_set_affine_coordinates_GFp fail\n");
        return NULL;
    }

    return key;
}

bool CertOp::VerifyDeviceSerialNumber(char* serial_number, size_t slen){
    if (!serial_number) {
        return COMMON_INVALID_PARAMS;
    }
    if (!serial_number || slen <DEVICE_ID_LENGTH ) {
        printf("VerifyDeviceSerialNumber: INVALID_PARAMS Failed!\n");
        return COMMON_INVALID_PARAMS;
    }
    std::fstream fs(DEVICE_SERIAL_NUMBER);
    if (!fs) {
        printf("VerifyDeviceSerialNumber: open file: %s Failed!\n", DEVICE_SERIAL_NUMBER);
        return COMMON_ERROR;
    }
    char sn[81];
    while (fs.peek() != EOF) {
        fs.getline(sn, 81);
        if(memcmp(serial_number, sn, slen) == 0){
            return COMMON_SUCCESS;
        }
    }
    fs.close();
    return COMMON_ERROR;
}

std::string CertOp::UnsignedLongToString(unsigned long t){
    std::ostringstream oss;  
    oss<<t;            
    return oss.str();   
}


unsigned int CertOp::UnsignedCharToInt(unsigned char* num){
    if (!num) {
        return 0;
    }
    int ret = num[3];
    ret += num[2] << 8;
    ret += num[1] << 16;
    ret += num[0] << 24;
    return ret;
}

unsigned char* CertOp::IntToUnsignedChar(unsigned int num){
    unsigned char *ret = (unsigned char* )malloc(4);
    if (!ret) {
        printf("IntToUnsignedChar malloc fail\n");
        return NULL;
    }
    ret[0] = num >> 24;
    ret[1] = num >> 16;
    ret[2] = num >> 8;
    ret[3] = num;
    return ret;
}

void CertOp::print_buffer(unsigned char* buffer, size_t blen){
    printf("\n");
    for (int i=0; i<blen; i++) {
        printf("0x%02x ", *(buffer+i));
    }
    printf("\n");
}

/**
* @}
**/
