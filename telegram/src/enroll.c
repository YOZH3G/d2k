#include "tg_enroll.h"
#include <openssl/sha.h>
#include <string.h>

int tg_enroll_proof(const tg_identity *identity, uint8_t out[TG_ENROLL_SIZE]) {
    static const uint8_t domain[]="d2k-enroll-v1"; /* Including NUL: domain separation. */
    uint8_t message[sizeof(domain)+56], digest[SHA256_DIGEST_LENGTH];
    if(!identity||strlen(identity->install_id_hex)!=32)return -1;
    for(size_t i=0;i<16;i++) {
        unsigned value=0;
        for(size_t j=0;j<2;j++) {
            char c=identity->install_id_hex[2*i+j];
            if(c>='0'&&c<='9')value=value*16+(unsigned)(c-'0');
            else if(c>='a'&&c<='f')value=value*16+(unsigned)(c-'a'+10);
            else return -1;
        }
        out[i]=(uint8_t)value;
    }
    if(tg_identity_public_key(identity,out+16)!=0)return -1;
    memcpy(message,domain,sizeof(domain));memcpy(message+sizeof(domain),out,48);
    /* 18-bit work, bound to this exact ID and key. A replay can only re-register
       the same identity; it cannot mint a second one or change its key. */
    for(uint64_t nonce=0;nonce<UINT64_C(16777216);nonce++) {
        for(size_t i=0;i<8;i++)out[48+i]=(uint8_t)(nonce>>(56-8*i));
        memcpy(message+sizeof(domain)+48,out+48,8);
        if(!SHA256(message,sizeof(message),digest))return -1;
        if(digest[0]==0&&digest[1]==0&&(digest[2]&0xc0)==0)
            return tg_identity_sign(identity,message,sizeof(message),out+56);
    }
    return -1;
}
