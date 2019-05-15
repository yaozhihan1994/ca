/***********************************************
* @addtogroup Nebula
* @{
* @file  : CertificateManage.h
* @brief :
* @date  : 2019-05-13
***********************************************/

//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------

#ifndef CERTIFICATE_H_
#define CERTIFICATE_H_

namespace CERTIFICATE{

#define ROOTCACRT "crts/rootCA.crt"
#define ROOTCAKEY "crts/rootCA.key"
#define SUBROOTCACRT "crts/SubrootCA.crt"
#define SUBROOTCAKEY "crts/SubrootCA.key"
#define ECACRT "crts/ECA.crt"
#define ECAKEY "crts/ECA.key"
#define PCACRT "crts/PCA.crt"
#define PCAKEY "crts/PCA.key"
#define RCACRT "crts/RCA.crt"
#define RCAKEY "crts/RCA.key"
#define CCACRT "crts/CCA.crt"
#define CCAKEY "crts/CCA.key"

#define PCRTS "pcrts/"
#define RCRTS "rcrts/"

#define SUBJECT_INFO_NAME "xingyunhulian"
#define PCA_POOL 5
#define RCA_POOL 5
#define DEVICE_SERIAL_NUMBER "device_serial_number"


#define CERTIFICATE_VERSION 2


class CertificateManage{
public:
    CertificateManage();
    ~CertificateManage();

    static int CertificateToFile(const char* filename, Certificate_t *crt);
    static Certificate_t* FileToCertificate(const char* filename);

    static int CertificateToBuffer(unsigned char** buffer, size_t* blen, Certificate_t *crt);
    static Certificate_t* BufferToCertificate(unsigned char* buffer, size_t blen);

    static int CertificateSign(EC_KEY* key, Certificate_t* crt);
    static int CertificateVerify(EC_KEY* key, Certificate_t* crt);

    static Certificate_t* CreateCertificate(e_CertificateType ctype, e_SubjectType  stype, unsigned char* public_key, unsigned char* sign_crt_hashid8, EC_KEY* sign_key);

    static void pcrt_manage();
    static void rcrt_manage();
    static void get_pcrt();
    static void get_rcrt();
    static void init_pcrt_list();
    static void init_rcrt_list();

    static int Init();

    static EC_KEY* rootca_key;

private:
    static list pcrt_list_;
    static list rcrt_list_;
    static pthread_mutex_t pcrt_mutex_;
    static pthread_mutex_t rcrt_mutex_;
};
}
#endif

/**
* @}
**/
