#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L
#include "tg_enroll.h"
#include <assert.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

int main(void) {
    char dir[]="/tmp/d2k-enroll-test-XXXXXX",path[256];assert(mkdtemp(dir));
    snprintf(path,sizeof(path),"%s/identity",dir);
    tg_identity id={0};assert(tg_identity_load_or_mint(path,&id)==0);
    uint8_t body[TG_ENROLL_SIZE],message[70],hash[32];
    assert(tg_enroll_proof(&id,body)==0);
    memcpy(message,"d2k-enroll-v1",14);memcpy(message+14,body,56);
    assert(SHA256(message,sizeof(message),hash));
    assert(hash[0]==0&&hash[1]==0&&(hash[2]&0xc0)==0);
    assert(tg_identity_verify(body+16,message,sizeof(message),body+56)==0);
    message[20]^=1;assert(tg_identity_verify(body+16,message,sizeof(message),body+56)!=0);
    tg_identity_cleanup(&id);unlink(path);rmdir(dir);
    puts("per-install proof: work and signature verified");return 0;
}
