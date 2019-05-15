#include "CertificateAndCrl.h"
#include "Common.h"
#include "CommonError.h"
#include "Init.h"
#include "Message.h"

#include <pthread.h>
#include <map>

using namespace std;

unsigned long crl_sn = 0;

bool crl_pthread_flag = false;
bool pca_pthread_flag = false;
bool rca_pthread_flag = false;

pthread_mutex_t crl_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t pca_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t rca_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t pca_cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t rca_cond = PTHREAD_COND_INITIALIZER;

EC_KEY* root_key = NULL;
EC_KEY* subroot_key = NULL;
EC_KEY* eca_key = NULL;
EC_KEY* pca_key = NULL;
EC_KEY* rca_key = NULL;
EC_KEY* cca_key = NULL;

Certificate_t* root_crt = NULL;
Certificate_t* subroot_crt = NULL;
Certificate_t* eca_crt = NULL;
Certificate_t* pca_crt = NULL;
Certificate_t* rca_crt = NULL;
Certificate_t* cca_crt = NULL;

unsigned char* rootca_buff = NULL;
unsigned char* subrootca_buff = NULL;
unsigned char* eca_buff = NULL;
unsigned char* pca_buff = NULL;
unsigned char* rca_buff = NULL;
unsigned char* cca_buff = NULL;

size_t rootca_buff_len = 0;
size_t subrootca_buff_len = 0;
size_t eca_buff_len = 0;
size_t pca_buff_len = 0;
size_t rca_buff_len = 0;
size_t cca_buff_len = 0;

unsigned char* rootca_hash = NULL;
unsigned char* subrootca_hash = NULL;
unsigned char* eca_hash = NULL;
unsigned char* pca_hash = NULL;
unsigned char* rca_hash = NULL;
unsigned char* cca_hash = NULL;

size_t rootca_hash_len = 0;
size_t subrootca_hash_len = 0;
size_t eca_hash_len = 0;
size_t pca_hash_len = 0;
size_t rca_hash_len = 0;
size_t cca_hash_len = 0;

//end time -- end_time/filename
map<string, unsigned long> map_crl;
//pri -- end_time/filename
map<string, unsigned long> map_pca;
map<string, unsigned long> map_rca;

void* CrlManageThread(void* args){
    printf("CrlManageThread start init\n");
    DIR* dir = opendir(CRL_FILENAME);
    dirent* p = NULL;
    map_crl.clear();
    while((p = readdir(dir)) != NULL){
        if(p->d_name[0] != '.'){
            unsigned long end_time = 0;
            string fname(p->d_name);
            stringstream ss;
            ss<<fname;
            ss>>end_time;
            map_crl.insert(pair<string, unsigned long>(fname, end_time));
        }
    }
    closedir(dir);
    printf("CrlManageThread init end\n");
    crl_pthread_flag = true;
    printf("CrlManageThread map_crl size: %d \n", map_crl.size());

    while (true) {
        time_t time_now = get_time_now();
        struct tm *tm_now = gmtime(&time_now);
        if (tm_now->tm_hour == 2) {
            pthread_mutex_lock(&crl_mutex);
            for (map<string, unsigned long>::iterator i=map_crl.begin(); i != map_crl.end(); i++){
                if (i->second <= time_now){
                    string name(CRL_FILENAME);
                    name+=i->first;
                    remove(name.c_str());
                    map_crl.erase(i);
                }
                usleep(1);
            }
            pthread_mutex_unlock(&crl_mutex);
        }
        sleep(60*60);
    }
   printf("CrlManageThread end\n");
}

void* PcaManageThread(void *arg ){
    printf("PcaManageThread start init\n");
    DIR* dir = opendir(PCA_CRTS);
    dirent* p = NULL;
    map_pca.clear();
    while((p = readdir(dir)) != NULL){
        if(p->d_name[0] != '.'){
            string cname(PCA_CRTS);
            string kname(PCA_KEYS);
            string fname(p->d_name);
            cname+=fname;
            kname+=fname;
            unsigned char* buf = NULL;
            size_t blen = 0;
            if(FileToBuffer(kname.c_str(), &buf, &blen) != COMMON_SUCCESS){
                printf("PcaManageThread FileToBuffer init fail\n");
                return;
            }
            unsigned char pri[32] = {};
            memcpy(pri, buf, 32);
            string spri((char*)pri);
            unsigned long end_time = 0;
            stringstream ss;
            ss<<fname;
            ss>>end_time;
            map_pca.insert(pair<string, unsigned long>(spri, end_time));
            free(buf);
        }
    }
    closedir(dir);
    printf("PcaManageThread init end\n");
    printf("PcaManageThread map_pca size: %d \n", map_pca.size());

    EC_KEY* key = NULL;
    Certificate_t* crt = NULL;

    if(GetCaAndKeyFromFile(PCACRT, PCAKEY, &crt, &key) != COMMON_SUCCESS){
        printf("PcaManageThread: GetCaAndKeyFromFile pca fail\n");
        return 0;
    }

    while (true) {
        unsigned long end_time = 0;
        unsigned char* pri = NULL;
        if (map_pca.size() < PCA_POOL) {
            if(CreateCRT(crt, key, SubjectType_authorizationTicket, PCA_CRTS, PCA_KEYS, &end_time, &pri) != COMMON_SUCCESS){
                printf("PcaManageThread: CreateSubCA pca fail\n");
                break;
            }
            printf("PcaManageThread: CreateSubCA pca succ\n");
            if (end_time ==0 || !pri) {
                printf("PcaManageThread: CreateSubCA end_time ==0 || !pri \n");
                break;
            }
            string spri((char *)pri);
            pthread_mutex_lock(&pca_mutex);
            map_pca.insert(pair<string, unsigned long>(spri, end_time));
            cout<<"map_pca.size: "<<map_pca.size()<<endl; 
            pthread_mutex_unlock(&pca_mutex);
        }else{
            pca_pthread_flag = true;
        }
        sleep(1);

        time_t time_now = get_time_now();
        struct tm *tm_now = localtime(&time_now);
        if (tm_now->tm_hour == 2) {
            pthread_mutex_lock(&pca_mutex);
            for (map<string, unsigned long>::iterator i=map_pca.begin(); i != map_pca.end(); i++){
                if (i->second <= time_now){
                    string scrt(PCA_CRTS);
                    string skey(PCA_KEYS);
                    string tmp;
                    stringstream ss;
                    ss<<(i->second);
                    ss>>tmp;
                    scrt += tmp;
                    skey += tmp;
                    remove(scrt.c_str());
                    remove(skey.c_str());
                    map_pca.erase(i);
                }
                usleep(1);
            }
            pthread_mutex_unlock(&pca_mutex);
        }
    }
    printf("PcaManageThread end\n");
}

void* RcaManageThread(void *arg ){
    printf("RcaManageThread start\n");
    DIR* dir = opendir(RCA_CRTS);
    dirent* p = NULL;
    map_rca.clear();
    while((p = readdir(dir)) != NULL){
        if(p->d_name[0] != '.'){
            string cname(RCA_CRTS);
            string kname(RCA_KEYS);
            string fname(p->d_name);
            cname+=fname;
            kname+=fname;
            unsigned char* buf = NULL;
            size_t blen = 0;
            if(FileToBuffer(kname.c_str(), &buf, &blen) != COMMON_SUCCESS){
                printf("RcaManageThread FileToBuffer init fail\n");
                return;
            }
            unsigned char pri[32] = {};
            memcpy(pri, buf, 32);
            string spri((char*)pri);
            unsigned long end_time = 0;
            stringstream ss;
            ss<<fname;
            ss>>end_time;
            map_rca.insert(pair<string, unsigned long>(spri, end_time));
            free(buf);
        }
    }
    closedir(dir);
    printf("RcaManageThread init end\n");
    printf("RcaManageThread map_rca size: %d \n", map_rca.size());

    EC_KEY* key = NULL;
    Certificate_t* crt = NULL;

    if(GetCaAndKeyFromFile(RCACRT, RCAKEY, &crt, &key) != COMMON_SUCCESS){
        printf("RcaManageThread: GetCaAndKeyFromFile rca fail\n");
        return 0;
    }

    while (true) {
        unsigned long end_time = 0;
        unsigned char* pri = NULL;
        if (map_rca.size() < PCA_POOL) {
            if(CreateCRT(crt, key, SubjectType_authorizationTicket, RCA_CRTS, RCA_KEYS, &end_time, &pri) != COMMON_SUCCESS){
                printf("RcaManageThread: CreateSubCA pca fail\n");
                break;
            }
            if (end_time ==0 || !pri) {
                printf("RcaManageThread: CreateSubCA end_time ==0 || !pri \n");
                break;
            }
            string spri((char *)pri);
            pthread_mutex_lock(&rca_mutex);
            map_rca.insert(pair<string, unsigned long>(spri, end_time));
            cout<<"map_rca.size: "<<map_rca.size()<<endl; 
            pthread_mutex_unlock(&rca_mutex);
        }else{
            rca_pthread_flag = true;
        }
        sleep(1);

        time_t time_now = get_time_now();
        struct tm *tm_now = localtime(&time_now);
        if (tm_now->tm_hour == 0) {
            pthread_mutex_lock(&rca_mutex);
            for (map<string, unsigned long>::iterator i=map_rca.begin(); i != map_rca.end(); i++){
                if (i->second <= time_now){
                    string scrt(RCA_CRTS);
                    string skey(RCA_KEYS);
                    string tmp;
                    stringstream ss;
                    ss<<(i->second);
                    ss>>tmp;
                    scrt += tmp;
                    skey += tmp;
                    remove(scrt.c_str());
                    remove(skey.c_str());
                    map_rca.erase(i);
                }
                usleep(1);
            }
            pthread_mutex_unlock(&rca_mutex);
        }
    }
    printf("RcaManageThread end\n");
}

void* MessageManageThread(void *arg ){
    printf("MessageManageThread start\n");
    if (CreateSocket(IP_HOST, PORT_RECV, PORT_SEND) != COMMON_SUCCESS) {
            printf("MessageManageThread: CreateSocket Failed!\n");
            return 0;
    }

    fstream fs(CRL_SERIAL_NUMBER);
    if (!fs) {
            printf("MessageManageThread: open file :%s Failed!\n", CRL_SERIAL_NUMBER);
            return 0;
    }
    string str_csn;
    while(fs>>str_csn){
        crl_sn = strtoul(str_csn.c_str(), 0, 0); 
    }
    fs.close();

    unsigned char *buffer = (unsigned char*)malloc(1024);
    unsigned char *data = (unsigned char*)malloc(1024);
    size_t len = 1024;
    unsigned char cmd = 0xff;
    int dlen = 0;
    
    while (true) {
        if (crl_pthread_flag && pca_pthread_flag && rca_pthread_flag) {
            break;
        }
        sleep(1);
    }

    while (true) {
        memset(buffer, 0, len);
        memset(data, 0, len);
        printf("MessageManageThread: recvmsg start!\n");
        if (RecvMsg(&buffer, &len) != 0){
            printf("MessageManageThread: recvmsg Failed!\n");
            return 0;
        }
        printf("MessageManageThread: recvmsg: %d bits succ!\n", len);
        printf("MessageManageThread: DecodeMessage start!\n");
        if(DecodeMessage(buffer, len, &cmd, &data, &dlen) == COMMON_SUCCESS){
            printf("MessageManageThread: DecodeMessage succ!\n");
            printf("cmd: 0x%02x\n",cmd);
            switch (cmd) {
                case 0x00:{
                    printf("MessageManageThread: cmd = 0 !\n");
                    if (dlen == 1) {
                        int flag = (int)(*data);
                        if(SendMsgCmdC0(flag) != COMMON_SUCCESS){
                            printf("MessageManageThread: SendMsgCmdC0 Failed!\n");
                            SendErrorCode(cmd);
                            break;
                        }                                
                    }else{
                        SendErrorCode(cmd);
                    }
                    break;
                }
                case 0x01:{
                    printf("MessageManageThread: cmd = 1 !\n");
                    if (true){//(CheckID(data, dlen) == COMMON_SUCCESS){
                        unsigned char *key_crt = (unsigned char*)calloc(1024, sizeof(unsigned char));
                        size_t clen = 0;
                        if(CreateNewECA(eca_crt, eca_key, SubjectType_enrollmentCredential, key_crt, &clen) != COMMON_SUCCESS){
                            printf("MessageManageThread: CreateNewECA Failed!\n");
                            free(key_crt);
                            SendErrorCode(cmd);
                            break;
                        }
                        clen+=32;
                        if(SendMsg(key_crt, clen) != COMMON_SUCCESS){
                            printf("MessageManageThread: SendMsg new eca Failed!\n");
                            free(key_crt);
                            SendErrorCode(cmd);
                            break;
                        }
                        free(key_crt);
                    }else{
                        printf("MessageManageThread: id not exists!\n");
                        SendErrorCode(cmd);
                    }
                    break;
                }
                case 0x02:{
                    if(true){// (CheckECA(eca_key, data, dlen) == COMMON_SUCCESS){
                        time_t time_now = get_time_now();
                        pthread_mutex_lock(&pca_mutex);
                        if (!map_pca.empty()) {
                            for (map<string, unsigned long>::iterator i=map_pca.begin(); i != map_pca.end(); i++){
                                if (i->second > time_now){
                                    string cname(PCA_CRTS);
                                    string kname(PCA_KEYS);
                                    string name;
                                    stringstream ss;
                                    ss<<i->second;
                                    ss>>name;
                                    cout<<name<<endl;
                                    cname += name;
                                    kname += name;
                                    if(SendCaAndKeyByFileName(cname.c_str(), kname.c_str()) == COMMON_SUCCESS){
                                        map_pca.erase(i);
                                        remove(cname.c_str());
                                        remove(kname.c_str());
                                    }else{
                                        printf("MessageManageThread: SendCaAndKeyByFileName pca Failed!\n");
                                        SendErrorCode(cmd);
                                    }
                                    break;
                                }
                            }
                            pthread_mutex_unlock(&pca_mutex);
                        }else{
                            pthread_mutex_unlock(&pca_mutex);
                            printf("MessageManageThread: SendCaAndKeyByFileName pca Failed!\n");
                            SendErrorCode(cmd);
                        }
                    }else{
                        printf("MessageManageThread: ECA check Failed!\n");
                        SendErrorCode(cmd);
                    }
                    break;
                }
                case 0x03:{
                    if (true){//(CheckECA(eca_key, data, dlen) == COMMON_SUCCESS){
                        time_t time_now = get_time_now();
                        pthread_mutex_lock(&rca_mutex);
                        if (!map_rca.empty()) {
                            for (map<string, unsigned long>::iterator i=map_rca.begin(); i != map_rca.end(); i++){
                                if (i->second > time_now){
                                    string cname(RCA_CRTS);
                                    string kname(RCA_KEYS);
                                    string name;
                                    stringstream ss;
                                    ss<<i->second;
                                    ss>>name;
                                    cname += name;
                                    kname += name;
                                    if(SendCaAndKeyByFileName(cname.c_str(), kname.c_str()) == COMMON_SUCCESS){
                                        map_rca.erase(i);
                                        remove(cname.c_str());
                                        remove(kname.c_str());
                                    }else{
                                        printf("MessageManageThread: SendCaAndKeyByFileName rca Failed!\n");
                                        SendErrorCode(cmd);
                                    }
                                    break ;
                                }
                            }
                            pthread_mutex_unlock(&rca_mutex);
                        }else{
                            pthread_mutex_unlock(&rca_mutex);
                            printf("MessageManageThread: SendCaAndKeyByFileName rca Failed!\n");
                            SendErrorCode(cmd);
                        }
                    }else{
                        printf("MessageManageThread: ECA check Failed!\n");
                        SendErrorCode(cmd);
                    }
                    break;
                }
                case 0x04:{
                    unsigned char ecrt_l[4] = {};
                    memcpy(ecrt_l, data, 4);
                    unsigned int elen = UnsignedCharToInt(ecrt_l);
                    unsigned char ecrt[elen];
                    memcpy(ecrt, data+4, elen);

                    unsigned char eca_l[4] = {};
                    memcpy(eca_l, data+4+elen, 4);
                    unsigned int ecalen = UnsignedCharToInt(eca_l);
                    unsigned char eca[ecalen];
                    memcpy(eca, data+4+elen+4, ecalen);

                    unsigned long sign_time = 0;
                    unsigned long end_time = 0;
                    if (CheckECA(eca_key, eca, ecalen) == COMMON_SUCCESS) {
                        unsigned char* hash = NULL;
                        size_t hlen = 0;
                        if(Sm3Hash(ecrt, elen, &hash, &hlen) != COMMON_SUCCESS){
                            printf("MessageManageThread: hash Failed!\n");
                            SendErrorCode(cmd);
                            break;
                        }
                        Certificate_t* crt = BufferToCertificate(ecrt, elen);
                        if (get_time_by_diff(crt->validityRestrictions.choice.timeStartAndEnd.endValidity) < get_time_now()) {
                            printf("MessageManageThread: error crt end time!\n");
                            SendErrorCode(cmd);
                            break;
                        }
                        crl_sn++;
                        if(CreateCRL(cca_key, subrootca_hash, cca_hash, hash, crl_sn, 
                                     crt->validityRestrictions.choice.timeStartAndEnd.startValidity, &sign_time) != COMMON_SUCCESS){
                            printf("MessageManageThread: CreateCRL fail!\n");
                            SendErrorCode(cmd);
                            if (crt) {
                                ASN_STRUCT_FREE(asn_DEF_Certificate, crt);
                            }
                            break;
                        }

                        string stmp;
                        stringstream ss;
                        ss<<end_time;
                        ss>>stmp;
                        end_time = get_time_by_diff(crt->validityRestrictions.choice.timeStartAndEnd.endValidity);
                        pthread_mutex_lock(&crl_mutex);
                        map_crl.insert(pair<string, unsigned long>(stmp, end_time));
                        pthread_mutex_unlock(&crl_mutex);
                        if (crt) {
                            ASN_STRUCT_FREE(asn_DEF_Certificate, crt);
                        }
                        if(set_crl_serial_number(crl_sn) != COMMON_SUCCESS){
                            printf("MessageManageThread: set_crl_serial_number fail!\n");
                        }
                    } else {
                        printf("MessageManageThread: ECA check Failed!\n");
                        SendErrorCode(cmd);
                    }
                    break;
                }
                case 0x05:{
                    if (true){//(CheckECA(eca_key, data, dlen) == COMMON_SUCCESS){
                        int mlen = 0;
                        time_t time_now = get_time_now();
                        unsigned char* msg = (unsigned char*)calloc(1024*map_crl.size(), sizeof(unsigned char)); 
                        if (!msg) {
                            printf("MessageManageThread: calloc crl msg Failed!\n");
                            SendErrorCode(cmd);
                            break;
                        }

                        if (map_crl.empty()) {
                            printf("MessageManageThread: map crl empty Failed!\n");
                            SendErrorCode(cmd);
                            break;
                        }
                        pthread_mutex_lock(&crl_mutex);
                        for (map<string, unsigned long>::iterator i = map_crl.begin(); i != map_crl.end(); i++) {
                            if (true){//(i->second > time_now){
                                string name("crls/");
                                string tmp;
                                stringstream ss;
                                ss<<i->second;
                                ss>>tmp;
                                name+= tmp;
                                unsigned char* buf = NULL;
                                size_t blen = 0;
                                if(FileToBuffer(name.c_str(), &buf, &blen) != COMMON_SUCCESS){
                                    printf("MessageManageThread: FileToBuffer Failed!\n");
                                    free(msg);
                                    break;
                                }
                                unsigned char* blen_c = IntToUnsignedChar(blen);
                                memcpy(msg+mlen, blen_c, 4);
                                mlen+=4;
                                memcpy(msg+mlen, buf, blen);
                                mlen+=blen;
                                free(buf);
                                free(blen_c);
                            }
                            usleep(1);
                        }
                        pthread_mutex_unlock(&crl_mutex);
                        if (SendMsg(msg, mlen) != COMMON_SUCCESS) {
                            printf("MessageManageThread: SendMsg Failed!\n");
                            SendErrorCode(cmd);
                        }
                        free(msg);
                    }else{
                        printf("MessageManageThread: ECA check Failed!\n");
                        SendErrorCode(cmd);
                    }
                    break;
                }
                default: {
                    printf("MessageManageThread: unknow cmd Failed!\n");
                    break;
                }
            }
        }else{
            printf("MessageManageThread: DecodeMessage Failed!\n");
            usleep(1);
            continue;
        }
        usleep(1);
    }
    free(buffer);
    free(data);
    printf("MessageManageThread end\n");
}

int main(){

    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();
    
    cout<<"----------------------------------------------------------"<<endl;
    cout<<"-------------------------start-init----------------------"<<endl;
    if(CheckCA() != COMMON_SUCCESS){
    cout<<"-------------------------start-to-create-ca-----------------------"<<endl;
        if(Init() != COMMON_SUCCESS){
            printf("main: Init fail\n");
            return 0;
        }
        printf("main: Init succ\n");
    }
    cout<<"-----------------------fanish-init----------------------"<<endl;
    cout<<"-----------------------------------------------------------"<<endl;
    cout<<"-------------------------loading-ca-keys-and-crts-start---------------------"<<endl;

    if(LoadCaAndKeyFromFile(ROOTCACRT, ROOTCAKEY, &root_crt, &root_key, &rootca_buff, &rootca_buff_len) != COMMON_SUCCESS){
        printf("main: GetCaAndKeyFromFile root ca fail\n");
        return 0;
    }
    if(LoadCaAndKeyFromFile(SUBROOTCACRT, SUBROOTCAKEY, &subroot_crt, &subroot_key, &subrootca_buff, &subrootca_buff_len) != COMMON_SUCCESS){
        printf("main: GetCaAndKeyFromFile subroot ca fail\n");
        return 0;
    }
    if(LoadCaAndKeyFromFile(ECACRT, ECAKEY, &eca_crt, &eca_key, &eca_buff, &eca_buff_len) != COMMON_SUCCESS){
        printf("main: GetCaAndKeyFromFile eca fail\n");
        return 0;
    }
    if(LoadCaAndKeyFromFile(PCACRT, PCAKEY, &pca_crt, &pca_key, &pca_buff, &pca_buff_len) != COMMON_SUCCESS){
        printf("main: GetCaAndKeyFromFile pca fail\n");
        return 0;
    }
    if(LoadCaAndKeyFromFile(RCACRT, RCAKEY, &rca_crt, &rca_key, &rca_buff, &rca_buff_len) != COMMON_SUCCESS){
        printf("main: GetCaAndKeyFromFile rca fail\n");
        return 0;
    }
    if(LoadCaAndKeyFromFile(CCACRT, CCAKEY, &cca_crt, &cca_key,  &cca_buff, &cca_buff_len) != COMMON_SUCCESS){
        printf("main: GetCaAndKeyFromFile cca fail\n");
        return 0;
    }
    
    if (Sm3Hash(rootca_buff, rootca_buff_len, &rootca_hash, &rootca_hash_len) != COMMON_SUCCESS) {
        printf("main: Sm3Hash rootca fail\n");
        return 0;
    }
    if (Sm3Hash(subrootca_buff, subrootca_buff_len, &subrootca_hash, &subrootca_hash_len) != COMMON_SUCCESS) {
        printf("main: Sm3Hash subrootca fail\n");
        return 0;
    }
    if (Sm3Hash(eca_buff, eca_buff_len, &eca_hash, &eca_hash_len) != COMMON_SUCCESS) {
        printf("main: Sm3Hash eca fail\n");
        return 0;
    }
    if (Sm3Hash(pca_buff, pca_buff_len, &pca_hash, &pca_hash_len) != COMMON_SUCCESS) {
        printf("main: Sm3Hash pca fail\n");
        return 0;
    }
    if (Sm3Hash(rca_buff, rca_buff_len, &rca_hash, &rca_hash_len) != COMMON_SUCCESS) {
        printf("main: Sm3Hash rca fail\n");
        return 0;
    }
    if (Sm3Hash(cca_buff, cca_buff_len, &cca_hash, &cca_hash_len) != COMMON_SUCCESS) {
        printf("main: Sm3Hash cca fail\n");
        return 0;
    }
    cout<<"-------------------------loading-ca-keys-and-crts-finsh---------------------"<<endl;


    pthread_t pthread_pca, pthread_rca, pthread_crl, pthread_message;
//  pthread_attr_t attr;
//  pthread_attr_init(&attr);
//  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
     
//  pthread_create(&pthread_message, NULL, MessageManageThread, NULL);
//  pthread_create(&pthread_pca, NULL, PcaManageThread, NULL);
//  pthread_create(&pthread_rca, NULL, RcaManageThread, NULL);
//  pthread_create(&pthread_crl, NULL, CrlManageThread, NULL);
//
//  pthread_join(pthread_message, NULL);
//  pthread_join(pthread_pca, NULL);
//  pthread_join(pthread_rca, NULL);
//  pthread_join(pthread_crl, NULL);

    for (int k = 0; k<10; k++) {

        Crl_t *crl = (Crl_t*)CALLOC(1, sizeof(Crl_t));
        crl->version = CRL_VERSION;

        crl->signerInfo.present = SignerInfo_PR_certificateDigestWithSM3;
        crl->signerInfo.choice.certificateDigestWithSM3.buf = (uint8_t* )malloc(8);
        memcpy(crl->signerInfo.choice.certificateDigestWithSM3.buf, subrootca_hash, 8);
        crl->signerInfo.choice.certificateDigestWithSM3.size = 8;

        crl->unsignedCrl.caId.buf = (uint8_t* )malloc(8);
        memcpy(crl->unsignedCrl.caId.buf, cca_hash, 8);
        crl->unsignedCrl.caId.size = 8;

        crl->unsignedCrl.crlSerial = k;

        crl->unsignedCrl.startPeriod = get_diff_time_by_now();
        crl->unsignedCrl.issueDate = get_diff_time_by_now();
        crl->unsignedCrl.nextCrl = get_diff_time_by_now();

        crl->unsignedCrl.type.present = CrlType_PR_idOnly;
        crl->unsignedCrl.type.choice.idOnly.buf =  (uint8_t* )malloc(10);
        memcpy(crl->unsignedCrl.type.choice.idOnly.buf, subrootca_hash, 10);
        crl->unsignedCrl.type.choice.idOnly.size = 10;

        if(CrlSign(cca_key, crl) != COMMON_SUCCESS){
            cout<<"crl sign fail"<<endl;
            return 0;
        }

        unsigned char *buff = NULL;
        size_t blen  = 0;
        CrlToBuffer(&buff, &blen, crl);
        cout<<blen<<endl;
        for (int i = 0; i< blen; i++) {
            printf("0x%02x ", *(buff+i));
        }
        cout<<endl;
        string name("crls/");
        stringstream ss;
        ss<<k;
        string s;
        ss>>s;
        name+=s;
        if (CrlToFile(name.c_str(), crl)) {
            printf("CrlToFile fail\n");
            return 0;
        }
        ASN_STRUCT_FREE(asn_DEF_Crl, crl);
    }


    cout<<endl;
    /* Removes all digests and ciphers */
    EVP_cleanup();
    /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();

    return 0;
}

