/***********************************************
* @addtogroup Nebula
* @{
* @file  : Common.h
* @brief :
* @date  : 2019-04-25
***********************************************/

//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------


#ifndef COMMON_H_
#define COMMON_H_
#include <iostream>
#include <cstring>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctime>
#include <time.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/sm2.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>

#include "CommonError.h"
#include "CertificateAndCrl.h"
#include "asn/Certificate.h"
#include "asn/Crl.h"
#include "Init.h"

#define SM3_HASH_LENGTH 32
#define SM2_PUBLIC_KEY_LENGTH 65
#define SM2_PRIVATE_KEY_LENGTH 32
#define SM2_SIGN_MAX_LENGTH 72

#define CERTIFICATE_VERSION 2
#define CRL_VERSION 1

/**
 * @brief Create Sm2 Key Pair
 * 
 * @author yzh (4/19/2019)
 * @param  void
 * 
 * @return EC_KEY* -- succ,  NULL -- fail
 */ 
EC_KEY* CreateSm2KeyPair();


/**
 * @brief SM2 signature operation. Computes Z (user id digest) 
 *        and then signs H(Z || msg) using SM2
 * sm2 sign use same msg , id and key will get different sig 
 * because every time sm2 do sign , it use different random 
 * number k.  
 *  
 * @note sig_len = 70 - 72 
 *  
 * @author yzh (4/19/2019)
 * 
 * @param key (in) : sm2 key
 * @param id (in) : sm3 hash step 1: do hash to id , get Z
 * @param msg (in) : sm3 hash step 2: do hash to Z || msg 
 * @param msg_len (in) : the length of msg
 * @param sig (out) : signature
 * @param sig_len (out) :  the length of signature
 * 
 * @return int 0 -- succ, other -- fail 
 *  */ 
int SignData(EC_KEY* key, const char* id,  const unsigned char* msg, size_t msg_len, unsigned char** sig, size_t* sig_len);


/**
 * @brief Verify sm2 Signature
 * 
 * @author yzh (4/19/2019)
 * 
 * @param key (in) : sm2 key
 * @param sig (in) : signature
 * @param sig_len (in) : the length of signature
 * @param id (in) : sm3 hash step 1: do hash to id , get Z
 * @param msg (in) : sm3 hash step 2: do hash to Z || msg
 * @param msg_len (in) : the length of msg
 * 
 * @return  int 0 -- succ, other -- fail 
 */
int VerifySignedData(EC_KEY* key, const unsigned char* sig, size_t sig_len, const char* id, const unsigned char* msg, int msg_len);


/**
 * @brief Encrypt data by sm2 public key , sm3 do hash 
 * sm2 encrypto use same plaintext and key will get different 
 * cpihertext because every time sm2 do encrypto , it use 
 * different random number k. 
 *  
 * @note ciphertext_len = msg_len + (106...108)
 *  
 * @author yzh (4/19/2019)
 * 
 * @param key (in) : sm2 key
 * @param msg (in) : msg that needs to be Encrypted 
 * @param msg_len (in) : the length of msg
 * @param ciphertext (out) : Message encryption result
 * @param ciphertext_len (out) : the length of Message 
 *                       encryption result
 * 
 * @return  int 0 -- succ, other -- fail  
 * @warning  *ciphertext need be free when you do not need it
 */
int EncryptData(EC_KEY* key, const unsigned char* msg, size_t msg_len, unsigned char** ciphertext, size_t* ciphertext_len);


/**
 * @brief Decrypt data by sm2 private key , sm3 do hash
 * 
 * @author yzh (4/19/2019)
 * 
 * @param key (in) : sm2 key
 * @param ciphertext (in) : ciphertext that needs to be 
 *                   decrypted
 * @param ciphertext_len (in) : the length of ciphertext
 * @param plaintext (out) : Ciphertext decryption result
 * @param plaintext_len (out) : the length of ciphertext 
 *                      decryption result
 * 
 * @return  int 0 -- succ, other -- fail  
 * @warning  *plaintext need be free when you do not need it 
 */
int DecryptData(EC_KEY* key, const unsigned char* ciphertext, size_t ciphertext_len, unsigned char** plaintext, size_t* plaintext_len);



/**
 * @brief do Hash to messages by SM3, hash length is 32.
 * 
 * @author yzh (4/19/2019)
 * 
 * @param msg(in) : Need to do hash message
 * @param msg_len(in) : Need to do hash message length
 * @param hash(out) : hash result
 * @param hash_len(out) : hash result length
 * 
 * @return  int 0 -- succ, other -- fail  
 * @warning *hash need be free when you do not need it   
 */
int Sm3Hash(unsigned char* msg, size_t msg_len, unsigned char** hash, size_t* hash_len);


/**
 * @brief sm4 cbc mode, same input same output .
 * cbc block = 128bit(16Bit)  ciphertext_len max = msg_len + 16.
 * @author yzh (4/20/2019)
 * 
 * @param plaintext 
 * @param plaintext_len 
 * @param key 
 * @param iv 
 * @param ciphertext 
 * @param ciphertext_len 
 * 
 * @return  int 0 -- succ, other -- fail  
 * @warning  *ciphertext need be free when you do not need it  
 */
int EncryptDataBySm4Cbc(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                        unsigned char *iv, unsigned char **ciphertext, int* ciphertext_len);


/**
 * @brief sm4 ecb mode, same input same output .
 * ecb block = 128bit(16Bit)  ciphertext_len max = msg_len + 16.
 * @author yzh (4/20/2019)
 * 
 * @param plaintext 
 * @param plaintext_len 
 * @param key 
 * @param ciphertext 
 * @param ciphertext_len 
 * 
 * @return  int 0 -- succ, other -- fail  
 * @warning  *ciphertext need be free when you do not need it  
 */
int EncryptDataBySm4Ecb(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                        unsigned char **ciphertext, int* ciphertext_len);


/**
 * 
 * 
 * @author yzh (4/20/2019)
 * 
 * @param ciphertext 
 * @param ciphertext_len 
 * @param key 
 * @param iv 
 * @param plaintext 
 * @param plaintext_len 
 * 
 * @return  int 0 -- succ, other -- fail  
 * @warning  *ciphertext need be free when you do not need it 
 */
int DecryptDataBySm4Cbc(unsigned char *ciphertext, int ciphertext_len, unsigned char* key, 
                       unsigned char* iv, unsigned char** plaintext, int* plaintext_len);


/**
 * 
 * 
 * @author yzh (4/20/2019)
 * 
 * @param ciphertext 
 * @param ciphertext_len 
 * @param key 
 * @param plaintext 
 * @param plaintext_len 
 * 
 * @return  int 0 -- succ, other -- fail  
 * @warning  *ciphertext need be free when you do not need it 
 */
int DecryptDataBySm4Ecb(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, 
                        unsigned char** plaintext, int* plaintext_len);

/**
 * @brief use my ec key and other pub key(ec key) to compute a 
 *        key ,  length = 32, same input same output
 * @author yzh (4/25/2019) 
 *  
 * @param mkey (in) : my ec key 
 * @param okey (in) : other ec key 
 * @param key (out) : key 
 * @param keylen (out) : key length 
 * @return  int 0 -- succ, other -- fail 
 *  
 * @warning key need be free when you do not use it 
 */
int DeriveKey(EC_KEY* mkey, EC_KEY* okey, unsigned char** key, size_t* keylen);

/**
 * 
 * 
 * @author yzh (4/25/2019)
 * 
 * @param key 
 * 
 * @return unsigned char* -- succ  NULL -- fail
 */
unsigned char* get_sm2_public_key(const EC_KEY* key);


/**
 * 
 * 
 * @author yzh (4/25/2019)
 * 
 * @param key 
 * 
 * @return unsigned char* -- succ  NULL -- fail
 */
unsigned char* get_sm2_private_key(const EC_KEY* key);

unsigned long get_diff_time_by_now();

unsigned long get_diff_time_by_days(int day);

unsigned long get_diff_time_by_years(int year);

unsigned long get_time_now();

unsigned long get_time_by_diff(unsigned long diff);

int CertificateSign(EC_KEY* key, Certificate_t* crt);

int CertificateVerify(EC_KEY* key, Certificate_t* crt);

int CrlSign(EC_KEY* key, Crl_t* crl);

int KeyToFile(const char* filename, EC_KEY* key);

EC_KEY* FileToKey(const char* filename);

int FileToBuffer(const char* filename, unsigned char** buff, size_t* blen);

int CreateCRL(EC_KEY* key, unsigned char* subrootca_hash, unsigned char* cca_hash, unsigned char* hashid10, 
              unsigned long crl_serial_number, unsigned long crt_start_time,  unsigned long* sign_time);

#endif

/**
* @}
**/



