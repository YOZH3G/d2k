#include "d2k_update.h"
#include <limits.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

#define TOKEN_MAX 16384u
#define DEPTH_MAX 16u
/* JSON tokens refer only to already authenticated input. next skips descendants. */
typedef enum { OBJECT, ARRAY, STRING, NUMBER } kind;
typedef struct { kind type; size_t start, len, next, count; uint64_t number; } token;
typedef struct { const unsigned char *bytes; size_t len, pos, used; token *tokens; } parser;
static int ws(unsigned char c) { return c==' ' || c=='\t' || c=='\r' || c=='\n'; }
static void space(parser *p) { while(p->pos<p->len && ws(p->bytes[p->pos])) p->pos++; }
static int hex(unsigned char c) {
    if(c>='0'&&c<='9') return c-'0';
    if(c>='a'&&c<='f') return c-'a'+10;
    if(c>='A'&&c<='F') return c-'A'+10;
    return -1;
}
static int hex4(const unsigned char *s,uint32_t *v) {
    size_t i; *v=0; for(i=0;i<4;i++) { int x=hex(s[i]); if(x<0) return 0; *v=(*v<<4)|(unsigned)x; } return 1;
}
/* Decode and validate UTF-8, including escaped surrogate pairs. NUL and raw
 * controls are forbidden; every length below counts decoded UTF-8 bytes. */
static int string_value(const parser *p,const token *t,char *out,size_t cap,size_t *length) {
    size_t i=t->start,end=i+t->len,n=0;
    while(i<end) {
        uint32_t cp; unsigned char c=p->bytes[i++]; unsigned char encoded[4]; size_t z=0,j;
        if(c=='\\') {
            if(i==end) return 0;
            c=p->bytes[i++];
            if(c=='u') {
                if(end-i<4 || !hex4(p->bytes+i,&cp)) return 0;
                i+=4;
                if(cp>=0xd800 && cp<=0xdbff) {
                    uint32_t lo;
                    if(end-i<6 || p->bytes[i]!='\\' || p->bytes[i+1]!='u' || !hex4(p->bytes+i+2,&lo) || lo<0xdc00 || lo>0xdfff) return 0;
                    i+=6; cp=0x10000+((cp-0xd800)<<10)+(lo-0xdc00);
                } else if(cp>=0xdc00 && cp<=0xdfff) return 0;
            } else {
                switch(c) {
                case '"': case '\\': case '/': cp=c; break;
                case 'b': cp=8; break; case 'f': cp=12; break;
                case 'n': cp=10; break; case 'r': cp=13; break; case 't': cp=9; break;
                default: return 0;
                }
            }
        } else if(c<0x80) { if(c<0x20 || c=='"') return 0; cp=c; }
        else {
            unsigned need; uint32_t min;
            if(c>=0xc2 && c<=0xdf) {need=1;cp=c&31;min=0x80;}
            else if(c>=0xe0 && c<=0xef) {need=2;cp=c&15;min=0x800;}
            else if(c>=0xf0 && c<=0xf4) {need=3;cp=c&7;min=0x10000;}
            else return 0;
            if(end-i<need) return 0;
            for(j=0;j<need;j++) {c=p->bytes[i++]; if((c&0xc0)!=0x80) return 0; cp=(cp<<6)|(c&63);}
            if(cp<min || cp>0x10ffff || (cp>=0xd800 && cp<=0xdfff)) return 0;
        }
        if(!cp) return 0;
        if(cp<0x80) encoded[z++]=(unsigned char)cp;
        else if(cp<0x800) {encoded[z++]=0xc0|(cp>>6);encoded[z++]=0x80|(cp&63);}
        else if(cp<0x10000) {encoded[z++]=0xe0|(cp>>12);encoded[z++]=0x80|((cp>>6)&63);encoded[z++]=0x80|(cp&63);}
        else {encoded[z++]=0xf0|(cp>>18);encoded[z++]=0x80|((cp>>12)&63);encoded[z++]=0x80|((cp>>6)&63);encoded[z++]=0x80|(cp&63);}
        if(out && z>cap-n) return 0;
        if(out) memcpy(out+n,encoded,z);
        n+=z;
    }
    if(out) out[n]='\0';
    if(length) *length=n;
    return 1;
}
static int value(parser *,unsigned,size_t *);
static int parse_string(parser *p,size_t *id) {
    token *t; size_t start;
    if(p->used==TOKEN_MAX || p->pos>=p->len || p->bytes[p->pos++]!='"') return 0;
    *id=p->used++; t=&p->tokens[*id]; t->type=STRING; start=p->pos;
    while(p->pos<p->len && p->bytes[p->pos]!='"') {
        if(p->bytes[p->pos++]=='\\') { if(p->pos==p->len) return 0; p->pos++; }
    }
    if(p->pos==p->len) return 0;
    t->start=start; t->len=p->pos-start; t->next=p->used; p->pos++;
    return string_value(p,t,NULL,0,NULL);
}
static int value(parser *p,unsigned depth,size_t *id) {
    token *t; unsigned char c; size_t dummy;
    space(p); if(depth>DEPTH_MAX || p->pos==p->len || p->used==TOKEN_MAX) return 0;
    c=p->bytes[p->pos]; if(c=='"') return parse_string(p,id);
    *id=p->used++; t=&p->tokens[*id];
    if(c=='{' || c=='[') {
        unsigned char close=c=='{'?'}':']'; t->type=c=='{'?OBJECT:ARRAY; p->pos++; space(p);
        if(p->pos<p->len && p->bytes[p->pos]==close) { p->pos++; t->next=p->used; return 1; }
        for(;;) {
            if(t->type==OBJECT) {
                size_t key,prev; char name[65],other[65];
                if(!parse_string(p,&key) || !string_value(p,&p->tokens[key],name,64,NULL)) return 0;
                for(prev=*id+1;prev<key;prev=p->tokens[prev+1].next) {
                    if(!string_value(p,&p->tokens[prev],other,64,NULL) || !strcmp(name,other)) return 0;
                }
                space(p); if(p->pos==p->len || p->bytes[p->pos++]!=':') return 0;
            }
            if(!value(p,depth+1,&dummy)) return 0;
            t->count++; space(p); if(p->pos==p->len) return 0;
            c=p->bytes[p->pos++]; if(c==close) break;
            if(c!=',') return 0;
            space(p);
        }
    } else {
        uint64_t n=0; size_t start=p->pos;
        t->type=NUMBER;
        if(c<'0'||c>'9') return 0;
        do { unsigned digit=p->bytes[p->pos++]-'0'; if(n>(UINT64_MAX-digit)/10) return 0; n=n*10+digit; }
        while(p->pos<p->len && p->bytes[p->pos]>='0' && p->bytes[p->pos]<='9');
        if(p->pos-start>1 && c=='0') return 0;
        t->number=n;
    }
    t->next=p->used; return 1;
}
static int parse(parser *p,const void *data,size_t len) {
    size_t id; p->bytes=data;p->len=len;p->pos=0;p->used=0;
    if(!value(p,0,&id)) return 0;
    space(p); return p->pos==len && p->tokens[0].type==OBJECT;
}
/* Require a closed field set; fields[] receives value token indices. */
static int fields(parser *p,size_t object,const char *const *names,size_t count,size_t required,size_t *f) {
    size_t i,j; uint64_t seen=0;
    if(p->tokens[object].type!=OBJECT) return 0;
    for(i=0;i<count;i++) f[i]=SIZE_MAX;
    for(i=object+1;i<p->tokens[object].next;i=p->tokens[i+1].next) {
        char name[65]; if(!string_value(p,&p->tokens[i],name,64,NULL)) return 0;
        for(j=0;j<count;j++) if(!strcmp(name,names[j])) break;
        if(j==count) return 0;
        seen|=UINT64_C(1)<<j; f[j]=i+1;
    }
    return (seen & ((UINT64_C(1)<<required)-1))==((UINT64_C(1)<<required)-1);
}
static int number(parser *p,size_t i,uint64_t *n) {
    if(i==SIZE_MAX || p->tokens[i].type!=NUMBER) return 0;
    *n=p->tokens[i].number; return 1;
}
static int timestamp(parser *p,size_t i,int64_t *n) {
    uint64_t u; if(!number(p,i,&u) || u>INT64_MAX) return 0;
    *n=(int64_t)u; return 1;
}
static int text_field(parser *p,size_t i,char *s,size_t cap,size_t *n) {
    return i!=SIZE_MAX && p->tokens[i].type==STRING && string_value(p,&p->tokens[i],s,cap,n);
}
static int identifier(const char *s,size_t n) {
    size_t i; if(!n || !((s[0]>='a'&&s[0]<='z') || (s[0]>='A'&&s[0]<='Z') || (s[0]>='0'&&s[0]<='9'))) return 0;
    for(i=0;i<n;i++) if(!((s[i]>='a'&&s[i]<='z') || (s[i]>='A'&&s[i]<='Z') || (s[i]>='0'&&s[i]<='9') || s[i]=='.' || s[i]=='_' || s[i]=='-')) return 0;
    return 1;
}
static int path(const char *s,size_t n) {
    size_t i,start=0;
    if(!n || s[0]=='/' || s[n-1]=='/') return 0;
    for(i=0;i<=n;i++) {
        if(i==n || s[i]=='/') {
            size_t z=i-start;
            if(!z || (z==1&&s[start]=='.') || (z==2&&s[start]=='.'&&s[start+1]=='.')) return 0;
            start=i+1;
        } else if(!((s[i]>='a'&&s[i]<='z') || (s[i]>='A'&&s[i]<='Z') || (s[i]>='0'&&s[i]<='9') || s[i]=='.' || s[i]=='_' || s[i]=='-')) return 0;
    }
    return 1;
}
static int digest_field(parser *p,size_t i,unsigned char *out,size_t n) {
    char s[65]; size_t len,j;
    if(n>32 || !text_field(p,i,s,n*2,&len) || len!=n*2) return 0;
    for(j=0;j<n;j++) { int a=hex((unsigned char)s[j*2]),b=hex((unsigned char)s[j*2+1]);
        /* Published hashes are canonical lowercase hex. */
        if(a<0||b<0 || (s[j*2]>='A'&&s[j*2]<='F') || (s[j*2+1]>='A'&&s[j*2+1]<='F')) return 0;
        out[j]=(unsigned char)((a<<4)|b);
    }
    return 1;
}
static int abi_known(const char *s) {
    static const char *const names[]={"arm64","arm","mipsel","mips","mips64el","amd64","x86","ppc64","riscv64"};
    size_t i; for(i=0;i<9;i++) if(!strcmp(s,names[i])) return 1;
    return 0;
}
static d2ku_rc authenticate(d2ku_ctx *ctx,const void *data,size_t len,const unsigned char sig[64],int64_t *now,size_t *signer,unsigned char hash[32]) {
    size_t i; int matched=0; unsigned int n=0; d2ku_rc rc;
    if(!ctx->clock.wall || !ctx->trust_count || ctx->trust_count>D2KU_KEYS_MAX) return D2KU_INVALID;
    /* Never inspect signed bytes to select a key or learn a replacement. */
    for(i=0;i<ctx->trust_count;i++) {
        EVP_PKEY *key=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,ctx->trust[i].public_key,32);
        EVP_MD_CTX *md=EVP_MD_CTX_new(); int valid=0;
        if(!key || !md) { EVP_PKEY_free(key); EVP_MD_CTX_free(md); return D2KU_IO; }
        if(EVP_DigestVerifyInit(md,NULL,NULL,NULL,key)==1) valid=EVP_DigestVerify(md,sig,64,data,len)==1;
        EVP_MD_CTX_free(md); EVP_PKEY_free(key);
        if(!valid) continue;
        matched=1; rc=ctx->clock.wall(ctx->clock.arg,now); if(rc!=D2KU_OK) return D2KU_TIME;
        if(*now<0) return D2KU_TIME;
        if(ctx->trust[i].not_before<0 || ctx->trust[i].not_after<=ctx->trust[i].not_before) return D2KU_INVALID;
        if(*now<ctx->trust[i].not_before || *now>=ctx->trust[i].not_after) continue;
        *signer=i;
        if(EVP_Digest(data,len,hash,&n,EVP_sha256(),NULL)!=1 || n!=32) return D2KU_IO;
        return D2KU_OK;
    }
    return matched?D2KU_EXPIRED:D2KU_UNTRUSTED;
}
static d2ku_rc read_index(parser *p,d2ku_ctx *ctx,int64_t now,d2ku_index *out) {
    static const char *const names[]={"schema","channel","sequence","issued_at","expires_at","release_id","manifest_sha256"};
    size_t f[7]; char channel[65]; size_t channel_len;
    if(!fields(p,0,names,7,7,f) || !number(p,f[0],&out->schema) ||
       !text_field(p,f[1],channel,64,&channel_len) || !number(p,f[2],&out->sequence) ||
       !timestamp(p,f[3],&out->issued_at) || !timestamp(p,f[4],&out->expires_at) ||
       !text_field(p,f[5],out->release_id,D2KU_ID_MAX,&out->release_id_len) ||
       !identifier(out->release_id,out->release_id_len) || !digest_field(p,f[6],out->manifest_sha256,32) ||
       !out->sequence || out->issued_at>=out->expires_at) return D2KU_INVALID;
    if(out->schema!=1 || strcmp(channel,"stable")) return D2KU_INCOMPATIBLE;
    memcpy(out->channel,channel,channel_len+1); out->channel_len=channel_len;
    if(now>=out->expires_at) return D2KU_EXPIRED;
    if(now<out->issued_at) return D2KU_TIME;
    if(out->sequence<ctx->accepted_sequence) return D2KU_REPLAY;
    if(out->sequence==ctx->accepted_sequence && (!ctx->has_accepted_index || memcmp(out->document_sha256,ctx->accepted_index_sha256,32))) return D2KU_REPLAY;
    return D2KU_OK;
}
static int read_file(parser *p,size_t id,d2ku_file *out) {
    static const char *const names[]={"path","size","mode","sha256"}; size_t f[4]; uint64_t mode;
    if(!fields(p,id,names,4,4,f) || !text_field(p,f[0],out->path,D2KU_PATH_MAX,&out->path_len) ||
       !path(out->path,out->path_len) || !number(p,f[1],&out->size) || !number(p,f[2],&mode) ||
       (mode!=0644 && mode!=0755) || !digest_field(p,f[3],out->sha256,32)) return 0;
    out->mode=(uint32_t)mode; return 1;
}
static int read_package(parser *p,size_t id,d2ku_manifest *m) {
    static const char *const names[]={"abi","artifact","size","sha256","files"}; size_t f[5],i,j;
    d2ku_package *out; uint64_t total=0;
    if(m->package_count==D2KU_PACKAGES_MAX) return 0;
    out=&m->packages[m->package_count];
    if(!fields(p,id,names,5,5,f) || !text_field(p,f[0],out->abi,D2KU_ABI_MAX,&out->abi_len) || !abi_known(out->abi) ||
       !text_field(p,f[1],out->artifact,D2KU_PATH_MAX,&out->artifact_len) || !path(out->artifact,out->artifact_len) ||
       !number(p,f[2],&out->size) || !out->size || !digest_field(p,f[3],out->sha256,32) ||
       p->tokens[f[4]].type!=ARRAY || !p->tokens[f[4]].count) return 0;
    for(i=0;i<m->package_count;i++) if(!strcmp(m->packages[i].abi,out->abi) || !strcmp(m->packages[i].artifact,out->artifact)) return 0;
    out->file_offset=m->file_count;
    for(i=f[4]+1;i<p->tokens[f[4]].next;i=p->tokens[i].next) {
        d2ku_file *file;
        if(m->file_count==D2KU_FILES_MAX) return 0;
        file=&m->files[m->file_count];
        if(!read_file(p,i,file) || file->size>out->size-total) return 0;
        total+=file->size;
        for(j=out->file_offset;j<m->file_count;j++) {
            size_t a=file->path_len,b=m->files[j].path_len;
            if(!strcmp(file->path,m->files[j].path) ||
               (a<b && !memcmp(file->path,m->files[j].path,a) && m->files[j].path[a]=='/') ||
               (b<a && !memcmp(file->path,m->files[j].path,b) && file->path[b]=='/')) return 0;
        }
        m->file_count++; out->file_count++;
    }
    m->package_count++; return 1;
}
static int read_keys(parser *p,size_t id,d2ku_ctx *ctx,int64_t now,d2ku_manifest *m) {
    static const char *const names[]={"public_key","not_before","not_after"}; size_t i,j,new_count=0;
    if(p->tokens[id].type!=ARRAY || !p->tokens[id].count || p->tokens[id].count>D2KU_KEYS_MAX) return 0;
    for(i=id+1;i<p->tokens[id].next;i=p->tokens[i].next) {
        size_t f[3]; d2ku_key *key=&m->signing_keys[m->signing_key_count]; int known=0;
        if(!fields(p,i,names,3,3,f) || !digest_field(p,f[0],key->public_key,32) ||
           !timestamp(p,f[1],&key->not_before) || !timestamp(p,f[2],&key->not_after) ||
           key->not_after<=now || key->not_after<=key->not_before ||
           key->not_before>=ctx->trust[m->signing_key_index].not_after ||
           key->not_after<=ctx->trust[m->signing_key_index].not_before) return 0;
        for(j=0;j<m->signing_key_count;j++) if(!memcmp(key->public_key,m->signing_keys[j].public_key,32)) return 0;
        for(j=0;j<ctx->trust_count;j++) if(!memcmp(key->public_key,ctx->trust[j].public_key,32)) {
            if(key->not_before!=ctx->trust[j].not_before || key->not_after!=ctx->trust[j].not_after) return 0;
            known=1;
        }
        if(!known) new_count++;
        m->signing_key_count++;
    }
    return ctx->trust_count+new_count<=D2KU_KEYS_MAX;
}
static d2ku_rc read_manifest(parser *p,d2ku_ctx *ctx,int64_t now,d2ku_manifest *out) {
    static const char *const names[]={"schema","release_id","version","commit","built_at","notes","min_updater","wire","state","packages","signing_keys"};
    size_t f[11],i; unsigned char commit[20]; int compatible_abi=0;
    if(!fields(p,0,names,11,10,f) || !number(p,f[0],&out->schema) ||
       !text_field(p,f[1],out->release_id,D2KU_ID_MAX,&out->release_id_len) || !identifier(out->release_id,out->release_id_len) ||
       !text_field(p,f[2],out->version,D2KU_VERSION_MAX,&out->version_len) || !out->version_len ||
       !digest_field(p,f[3],commit,20) || !text_field(p,f[3],out->commit,40,&out->commit_len) ||
       !timestamp(p,f[4],&out->built_at) || !text_field(p,f[5],out->notes,D2KU_NOTES_MAX,&out->notes_len) ||
       !number(p,f[6],&out->min_updater) || !number(p,f[7],&out->wire) || !number(p,f[8],&out->state) ||
       !out->min_updater || !out->wire || !out->state || p->tokens[f[9]].type!=ARRAY || !p->tokens[f[9]].count) return D2KU_INVALID;
    if(out->schema!=1) return D2KU_INCOMPATIBLE;
    if(out->built_at>now) return D2KU_TIME;
    for(i=f[9]+1;i<p->tokens[f[9]].next;i=p->tokens[i].next) if(!read_package(p,i,out)) return D2KU_INVALID;
    if(f[10]!=SIZE_MAX && !read_keys(p,f[10],ctx,now,out)) return D2KU_INVALID;
    for(i=0;i<out->package_count;i++) if(!strcmp(out->packages[i].abi,ctx->abi)) compatible_abi=1;
    if(!compatible_abi || out->min_updater>ctx->updater_version || out->wire!=ctx->wire_version || out->state!=ctx->state_version) return D2KU_INCOMPATIBLE;
    return D2KU_OK;
}
d2ku_rc d2ku_verify_index(d2ku_ctx *ctx,const void *data,size_t len,const unsigned char sig[64],d2ku_index *out) {
    parser p={0}; d2ku_index result={0}; int64_t now; size_t signer; d2ku_rc rc;
    if(!ctx || !data || !len || len>D2KU_INDEX_MAX || !sig || !out) return D2KU_INVALID;
    rc=authenticate(ctx,data,len,sig,&now,&signer,result.document_sha256); if(rc!=D2KU_OK) return rc;
    p.tokens=calloc(TOKEN_MAX,sizeof(*p.tokens)); if(!p.tokens) return D2KU_IO;
    rc=parse(&p,data,len)?read_index(&p,ctx,now,&result):D2KU_INVALID;
    free(p.tokens); if(rc==D2KU_OK) *out=result; return rc;
}
d2ku_rc d2ku_verify_manifest(d2ku_ctx *ctx,const void *data,size_t len,const unsigned char sig[64],d2ku_manifest *out) {
    parser p={0}; d2ku_manifest *result; int64_t now; size_t signer; unsigned char hash[32]; d2ku_rc rc;
    if(!ctx || !data || !len || len>D2KU_MANIFEST_MAX || !sig || !out ||
       !memchr(ctx->abi,0,sizeof(ctx->abi)) || !abi_known(ctx->abi)) return D2KU_INVALID;
    rc=authenticate(ctx,data,len,sig,&now,&signer,hash); if(rc!=D2KU_OK) return rc;
    result=calloc(1,sizeof(*result)); p.tokens=calloc(TOKEN_MAX,sizeof(*p.tokens));
    if(!result || !p.tokens) { free(result); free(p.tokens); return D2KU_IO; }
    memcpy(result->document_sha256,hash,32); result->signing_key_index=signer;
    rc=parse(&p,data,len)?read_manifest(&p,ctx,now,result):D2KU_INVALID;
    free(p.tokens); if(rc==D2KU_OK || (rc==D2KU_INCOMPATIBLE && result->schema==1)) *out=*result; free(result); return rc;
}
