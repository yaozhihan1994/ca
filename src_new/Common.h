/***********************************************
* @addtogroup Nebula
* @{
* @file  : Common.h
* @brief :
* @date  : 2019-05-13
***********************************************/

//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------

#ifndef COMMON_H_
#define COMMON_H_

namespace COMMON{

#define DIFFTIME_2004 1075564800
#define CA_CRT_VALIDITY_PERIOD_YEARS 10 
#define DEVICE_CRT_VALIDITY_PERIOD_DAYS 7
#define SIGNATURE_LENGTH 32
#define PUBLIC_KEY_LENGTH 32
#define SM3_HASH_LENGTH 32
#define CERTIFICATE_DGST_WITH_SM3_LENGTH 8

typedef enum CommonError
{
	COMMON_SUCCESS = 0,
	COMMON_ERROR = -1,
	COMMON_INVALID_PARAMS = -2,
	COMMON_NULL_POINT = -3,

} e_CommonError;

typedef enum CertificateType
{
	ROOT_CA = 0,
	SUBROOT_CA = 1,
	E_CA = 2,
	P_CA = 3,
    	R_CA = 4,
    	C_CA = 5,

} e_CertificateType;

class Common{
public:
    Common();
    ~Common();

    static int uper_callback(const void *buffer, size_t size, void *key);

    static EC_KEY* CreateSm2KeyPair();

    static int SignData(EC_KEY* key, const char* id,  const unsigned char* msg, size_t msg_len, unsigned char** sig, size_t* sig_len);

    static int VerifySignedData(EC_KEY* key, const unsigned char* sig, size_t sig_len, const char* id, const unsigned char* msg, int msg_len);

    static int EncryptData(EC_KEY* key, const unsigned char* msg, size_t msg_len, unsigned char** ciphertext, size_t* ciphertext_len);

    static int DecryptData(EC_KEY* key, const unsigned char* ciphertext, size_t ciphertext_len, unsigned char** plaintext, size_t* plaintext_len);

    static int Sm3Hash(unsigned char* msg, size_t msg_len, unsigned char** hash, size_t* hash_len);

    static int EncryptDataBySm4(SymmetricAlgorithm type, unsigned char *plaintext, int plaintext_len, unsigned char *key,
                                                           unsigned char *iv, unsigned char **ciphertext, int* ciphertext_len);
    static int DecryptDataBySm4(SymmetricAlgorithm type, unsigned char *ciphertext, int ciphertext_len, unsigned char* key, 
                                                           unsigned char* iv, unsigned char** plaintext, int* plaintext_len);
    static int DeriveKey(EC_KEY* mkey, EC_KEY* okey, unsigned char** key, size_t* keylen);

    static unsigned char* get_sm2_public_key(const EC_KEY* key);

    static unsigned char* get_sm2_private_key(const EC_KEY* key);

    static unsigned long get_difftime_by_now();

    static unsigned long get_difftime_by_days(int days);

    static unsigned long get_difftime_by_years(int years);

    static unsigned long get_time_now();

    static int get_hour_now();

    static unsigned long get_time_by_diff(unsigned long diff);

    static int FileToBuffer(const char* filename, unsigned char** buff, size_t* blen);

    static int BufferToFile(const char* filename, unsigned char* buff, size_t blen);

    static bool VerifyDeviceSerialNumber(unsigned char* serial_number, size_t slen);

    static void SplitString(const std::string& s, vector<std::string>& v, const std::string& c);

    static template<class T> string ToString(const T& t);

    static unsigned int UnsignedCharToInt(unsigned char* num);

    static unsigned char* IntToUnsignedChar(unsigned int num);

};
}
#endif

/**
* @}
**/

