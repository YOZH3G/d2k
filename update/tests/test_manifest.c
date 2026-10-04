/* Test-only deterministic Ed25519 seeds. Never use these for releases. */
#include "d2k_update.h"
#include <assert.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char index_json[] = "{\"schema\":1,\"channel\":\"stable\",\"sequence\":2,\"issued_at\":100,\"expires_at\":200,\"release_id\":\"r2\",\"manifest_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}";
static const char manifest_json[] = "{\"schema\":1,\"release_id\":\"r2\",\"version\":\"1.2.3\",\"commit\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"built_at\":100,\"notes\":\"Исправления\\nTLS\",\"min_updater\":1,\"wire\":1,\"state\":1,\"packages\":[{\"abi\":\"arm64\",\"artifact\":\"d2k-arm64.tar\",\"size\":2048,\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"files\":[{\"path\":\"bin/d2kc\",\"size\":3,\"mode\":493,\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}]}]}";
static unsigned char seed[32];
static int64_t wall_now = 150;
static d2ku_rc wall_result = D2KU_OK;
static d2ku_rc wall(void *arg, int64_t *out) { (void)arg; *out = wall_now; return wall_result; }
static void sign_bytes(const void *data, size_t len, unsigned char sig[64]) {
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, sizeof(seed));
    EVP_MD_CTX *md = EVP_MD_CTX_new(); size_t n = 64;
    assert(key && md && EVP_DigestSignInit(md, NULL, NULL, NULL, key) == 1);
    assert(EVP_DigestSign(md, sig, &n, data, len) == 1 && n == 64);
    EVP_MD_CTX_free(md); EVP_PKEY_free(key);
}
static d2ku_ctx context(void) {
    d2ku_ctx ctx = {0}; EVP_PKEY *key; size_t n = 32;
    memset(seed, 7, sizeof(seed));
    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, sizeof(seed));
    ctx.root_dirfd = -1; ctx.clock.wall = wall;
    ctx.trust_count = 1; ctx.trust[0].not_before = 50; ctx.trust[0].not_after = 250;
    assert(key && EVP_PKEY_get_raw_public_key(key, ctx.trust[0].public_key, &n) == 1);
    EVP_PKEY_free(key); strcpy(ctx.abi, "arm64");
    ctx.updater_version = 1; ctx.wire_version = 1; ctx.state_version = 1;
    ctx.accepted_sequence = 1; return ctx;
}
static char *replace(const char *s, const char *old, const char *new_value) {
    const char *p = strstr(s, old); size_t a, b; char *out;
    assert(p); a = (size_t)(p-s); b = strlen(p+strlen(old));
    out = malloc(a+strlen(new_value)+b+1); assert(out);
    memcpy(out,s,a); memcpy(out+a,new_value,strlen(new_value));
    memcpy(out+a+strlen(new_value),p+strlen(old),b+1); return out;
}
static void expect_index(d2ku_ctx *ctx, const char *json, d2ku_rc expected) {
    unsigned char sig[64]; d2ku_index out; sign_bytes(json,strlen(json),sig);
    memset(&out,0xa5,sizeof(out)); d2ku_rc rc=d2ku_verify_index(ctx,json,strlen(json),sig,&out); if(rc!=expected) fprintf(stderr,"index rc=%d expected=%d: %s\n",rc,expected,json); assert(rc==expected);
    if (expected!=D2KU_OK) assert(out.sequence == UINT64_C(0xa5a5a5a5a5a5a5a5));
}
static void bad_index(d2ku_ctx *ctx,const char *old,const char *value,d2ku_rc rc) {
    char *s=replace(index_json,old,value); expect_index(ctx,s,rc); free(s);
}
static void expect_manifest(d2ku_ctx *ctx,const char *json,d2ku_rc expected) {
    unsigned char sig[64]; d2ku_manifest *out=malloc(sizeof(*out)); assert(out);
    sign_bytes(json,strlen(json),sig); memset(out,0xa5,sizeof(*out));
    d2ku_rc rc=d2ku_verify_manifest(ctx,json,strlen(json),sig,out); if(rc!=expected) fprintf(stderr,"manifest rc=%d expected=%d: %s\n",rc,expected,json); assert(rc==expected);
    if(expected==D2KU_INCOMPATIBLE && strstr(json,"\"schema\":1")) {
        assert(out->schema==1); assert(!strcmp(out->release_id,"r2"));
        assert(!strcmp(out->version,"1.2.3")); assert(out->package_count>0);
    } else if(expected!=D2KU_OK) { const unsigned char *bytes=(const unsigned char *)out; for(size_t i=0;i<sizeof(*out);i++) assert(bytes[i]==0xa5); }
    else { assert(out->file_count>0); assert(out->packages[0].file_count==out->file_count); assert(out->packages[0].file_offset==0); }
    free(out);
}
static void bad_manifest(d2ku_ctx *ctx,const char *old,const char *value,d2ku_rc rc) {
    char *s=replace(manifest_json,old,value); expect_manifest(ctx,s,rc); free(s);
}

static void boundaries(d2ku_ctx *ctx) {
    char *s=malloc(D2KU_MANIFEST_MAX+2), *json, *notes; size_t i,n;
    assert(s);
    memcpy(s,index_json,strlen(index_json));
    memset(s+strlen(index_json),' ',D2KU_INDEX_MAX-strlen(index_json));
    s[D2KU_INDEX_MAX]=0; expect_index(ctx,s,D2KU_OK);
    s[D2KU_INDEX_MAX]=' '; s[D2KU_INDEX_MAX+1]=0; expect_index(ctx,s,D2KU_INVALID);
    memcpy(s,manifest_json,strlen(manifest_json));
    memset(s+strlen(manifest_json),' ',D2KU_MANIFEST_MAX-strlen(manifest_json));
    s[D2KU_MANIFEST_MAX]=0; expect_manifest(ctx,s,D2KU_OK);
    s[D2KU_MANIFEST_MAX]=' '; s[D2KU_MANIFEST_MAX+1]=0; expect_manifest(ctx,s,D2KU_INVALID);
    notes=malloc(D2KU_NOTES_MAX+2); assert(notes); memset(notes,'a',D2KU_NOTES_MAX+1);
    notes[D2KU_NOTES_MAX]=0; json=replace(manifest_json,"Исправления\\nTLS",notes);
    expect_manifest(ctx,json,D2KU_OK); free(json);
    notes[D2KU_NOTES_MAX]='a'; notes[D2KU_NOTES_MAX+1]=0;
    json=replace(manifest_json,"Исправления\\nTLS",notes); expect_manifest(ctx,json,D2KU_INVALID); free(json); free(notes);
    memset(s,'a',D2KU_PATH_MAX); s[D2KU_PATH_MAX]=0;
    json=replace(manifest_json,"bin/d2kc",s); expect_manifest(ctx,json,D2KU_OK); free(json);
    s[D2KU_PATH_MAX]='a'; s[D2KU_PATH_MAX+1]=0;
    json=replace(manifest_json,"bin/d2kc",s); expect_manifest(ctx,json,D2KU_INVALID); free(json);
    memset(s,'a',D2KU_ID_MAX+1); s[D2KU_ID_MAX+1]=0;
    json=replace(index_json,"r2",s); expect_index(ctx,json,D2KU_INVALID); free(json);
    const char *start=strstr(manifest_json,"{\"path\""); assert(start);
    n=(size_t)(start-manifest_json); memcpy(s,manifest_json,n);
    for(i=0;i<D2KU_FILES_MAX+1;i++) {
        int written=snprintf(s+n,D2KU_MANIFEST_MAX-n,"%s{\"path\":\"bin/f%zu\",\"size\":0,\"mode\":420,\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",i?",":"",i);
        assert(written>0); n+=(size_t)written;
        if(i==D2KU_FILES_MAX-1) { strcpy(s+n,"]}]}"); expect_manifest(ctx,s,D2KU_OK); }
    }
    strcpy(s+n,"]}]}"); expect_manifest(ctx,s,D2KU_INVALID); free(s);
}

int main(void) {
    d2ku_ctx ctx=context(); unsigned char sig[64]; d2ku_index out; char changed[sizeof(index_json)];
    expect_index(&ctx,index_json,D2KU_OK);
    sign_bytes(index_json,strlen(index_json),sig); memcpy(changed,index_json,sizeof(changed)); changed[10]='9';
    assert(d2ku_verify_index(&ctx,changed,strlen(changed),sig,&out)==D2KU_UNTRUSTED);
    /* Even malformed unsigned bytes must fail at the cryptographic boundary. */
    assert(d2ku_verify_index(&ctx,"{",1,sig,&out)==D2KU_UNTRUSTED);
    bad_index(&ctx,"\"sequence\":2","\"sequence\":1",D2KU_REPLAY);
    bad_index(&ctx,"\"sequence\":2","\"sequence\":18446744073709551616",D2KU_INVALID);
    bad_index(&ctx,"\"sequence\":2","\"sequence\":2.0",D2KU_INVALID);
    bad_index(&ctx,"\"schema\":1","\"schema\":2",D2KU_INCOMPATIBLE);
    bad_index(&ctx,"\"schema\":1","\"schema\":1,\"schema\":1",D2KU_INVALID);
    bad_index(&ctx,"\"schema\":1","\"schema\":1,\"sch\\u0065ma\":1",D2KU_INVALID);
    bad_index(&ctx,"\"release_id\":\"r2\"","\"release_id\":\"../r2\"",D2KU_INVALID);
    bad_index(&ctx,"\"expires_at\":200","\"expires_at\":150",D2KU_EXPIRED);
    bad_index(&ctx,"\"issued_at\":100","\"issued_at\":160",D2KU_TIME);
    bad_index(&ctx,"\"channel\":\"stable\"","\"channel\":\"nightly\"",D2KU_INCOMPATIBLE);
    bad_index(&ctx,"\"schema\":1","\"schema\":1,\"unknown\":1",D2KU_INVALID);
    sign_bytes(index_json,strlen(index_json),sig);
    assert(d2ku_verify_index(&ctx,index_json,strlen(index_json),sig,&out)==D2KU_OK);
    ctx.accepted_sequence=out.sequence; ctx.has_accepted_index=1;
    memcpy(ctx.accepted_index_sha256,out.document_sha256,32);
    expect_index(&ctx,index_json,D2KU_OK);
    char *reordered=replace(index_json,"{\"schema\":1","{ \"schema\":1");
    expect_index(&ctx,reordered,D2KU_REPLAY); free(reordered);
    ctx.accepted_sequence=1; ctx.has_accepted_index=0;
    wall_result=D2KU_TIME; expect_index(&ctx,index_json,D2KU_TIME); wall_result=D2KU_OK;
    wall_now=-1; expect_index(&ctx,index_json,D2KU_TIME); wall_now=150;
    ctx.trust[0].not_before=151; expect_index(&ctx,index_json,D2KU_EXPIRED); ctx.trust[0].not_before=50;
    ctx.trust[0].not_after=150; expect_index(&ctx,index_json,D2KU_EXPIRED); ctx.trust[0].not_after=250;
    expect_manifest(&ctx,manifest_json,D2KU_OK);
    bad_manifest(&ctx,"arm64","mips",D2KU_INCOMPATIBLE);
    bad_manifest(&ctx,"\"min_updater\":1","\"min_updater\":2",D2KU_INCOMPATIBLE);
    bad_manifest(&ctx,"\"state\":1","\"state\":2",D2KU_INCOMPATIBLE);
    bad_manifest(&ctx,"\"wire\":1","\"wire\":2",D2KU_INCOMPATIBLE);
    bad_manifest(&ctx,"bin/d2kc","../d2kc",D2KU_INVALID);
    bad_manifest(&ctx,"\"built_at\":100","\"built_at\":9223372036854775808",D2KU_INVALID);
    bad_manifest(&ctx,"\"schema\":1","\"schema\":2",D2KU_INCOMPATIBLE);
    bad_manifest(&ctx,"\"built_at\":100","\"built_at\":151",D2KU_TIME);
    bad_manifest(&ctx,"\"schema\":1","\"schema\":1,\"nested\":{\"x\":1,\"x\":2}",D2KU_INVALID);
    bad_manifest(&ctx,"\"size\":3","\"size\":2049",D2KU_INVALID);
    /* Both individually fit, but their total cannot fit the signed package. */
    bad_manifest(&ctx,"\"size\":3,\"mode\":493,\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        "\"size\":2048,\"mode\":493,\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},{\"path\":\"bin/other\",\"size\":2048,\"mode\":493,\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",D2KU_INVALID);
    bad_manifest(&ctx,"bin/d2kc","/bin/d2kc",D2KU_INVALID);
    bad_manifest(&ctx,"bin/d2kc","bin//d2kc",D2KU_INVALID);
    bad_manifest(&ctx,"\"mode\":493","\"mode\":2541",D2KU_INVALID);
    bad_manifest(&ctx,"\"mode\":493","\"mode\":493,\"mode\":420",D2KU_INVALID);
    bad_manifest(&ctx,"Исправления", "\\ud83d\\ude00",D2KU_OK);
    bad_manifest(&ctx,"Исправления", "\xc0\xaf",D2KU_INVALID);
    bad_manifest(&ctx,"Исправления", "\\ud800",D2KU_INVALID);
    bad_manifest(&ctx,"Исправления", "\\u0000",D2KU_INVALID);
    {
        char rotation[4096], hex[65]; d2ku_manifest *m=malloc(sizeof(*m));
        EVP_PKEY *key; unsigned char pub[32]; size_t n=32,i;
        memset(seed,8,32); key=EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,NULL,seed,32);
        assert(key && EVP_PKEY_get_raw_public_key(key,pub,&n)==1); EVP_PKEY_free(key);
        for(i=0;i<32;i++) snprintf(hex+2*i,sizeof(hex)-2*i,"%02x",pub[i]);
        snprintf(rotation,sizeof(rotation),"%.*s,\"signing_keys\":[{\"public_key\":\"%s\",\"not_before\":150,\"not_after\":400}]}",(int)strlen(manifest_json)-1,manifest_json,hex);
        /* A new key cannot authorise itself. */
        sign_bytes(rotation,strlen(rotation),sig);
        assert(d2ku_verify_manifest(&ctx,rotation,strlen(rotation),sig,m)==D2KU_UNTRUSTED);
        memset(seed,7,32); sign_bytes(rotation,strlen(rotation),sig);
        assert(d2ku_verify_manifest(&ctx,rotation,strlen(rotation),sig,m)==D2KU_OK);
        assert(m->signing_key_count==1 && !memcmp(m->signing_keys[0].public_key,pub,32));
        assert(ctx.trust_count==1); /* Caller must durably commit transitions. */
        ctx.trust[1]=m->signing_keys[0]; ctx.trust_count=2; memset(seed,8,32);
        expect_index(&ctx,index_json,D2KU_OK); memset(seed,7,32);
        char *s=replace(rotation,"\"not_before\":150","\"not_before\":250"); expect_manifest(&ctx,s,D2KU_INVALID); free(s);
        free(m);
    }
    strcpy(ctx.abi,"mips");
    bad_manifest(&ctx,"\"mode\":493","\"mode\":2541",D2KU_INVALID);
    strcpy(ctx.abi,"arm64");
    memset(ctx.abi,'a',sizeof(ctx.abi)); expect_manifest(&ctx,manifest_json,D2KU_INVALID); strcpy(ctx.abi,"arm64");
    boundaries(&ctx);
    puts("manifest: signature, strict schema, compatibility, replay, time and rotation PASS");
    return 0;
}
