#define _POSIX_C_SOURCE 200809L
#include "tg_config.h"

#include <ctype.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *trim(char *s) {
    while(isspace((unsigned char)*s))s++;
    size_t n=strlen(s);while(n&&isspace((unsigned char)s[n-1]))s[--n]='\0';
    return s;
}

static int copy_value(char *dst,size_t cap,const char *src) {
    size_t n=strlen(src);if(n>=cap)return -1;memcpy(dst,src,n+1);return 0;
}

static int normalize_shell_value(char *value) {
    size_t n=strlen(value);
    if(!n)return 0;
    if(value[0]=='\''||value[0]=='"') {
        if(n<2||value[n-1]!=value[0])return -1;
        char quote=value[0];value[n-1]='\0';memmove(value,value+1,n-1);
        if(strchr(value,quote))return -1;
    } else if(value[n-1]=='\''||value[n-1]=='"')return -1;
    return 0;
}

int tg_relay_url_parse(const char *url,tg_relay_url *out) {
    static const char prefix[]="wss://";
    if(!url||!out||strncmp(url,prefix,sizeof(prefix)-1)!=0)return -1;
    const char *authority=url+sizeof(prefix)-1,*slash=strchr(authority,'/');
    if(!slash||strcmp(slash,"/ws")!=0||slash==authority)return -1;
    size_t authority_len=(size_t)(slash-authority);if(authority_len>=320)return -1;
    char auth[320];memcpy(auth,authority,authority_len);auth[authority_len]='\0';
    if(strchr(auth,'@')||strchr(auth,'?')||strchr(auth,'#')||strchr(auth,'[')||strchr(auth,']'))return -1;
    char *colon=strrchr(auth,':');unsigned long port=443;
    if(colon){
        if(strchr(auth,':')!=colon||!colon[1])return -1;
        *colon++='\0';
        for(const char *p=colon;*p;p++)if(!isdigit((unsigned char)*p))return -1;
        errno=0;port=strtoul(colon,NULL,10);if(errno||port==0||port>65535)return -1;
    }
    size_t host_len=strlen(auth);if(!host_len||host_len>=sizeof(out->host))return -1;
    size_t label_start=0;
    for(size_t i=0;i<=host_len;i++) {
        if(i<host_len) {
            unsigned char c=(unsigned char)auth[i];
            if(!(isalnum(c)||c=='.'||c=='-'))return -1;
            if(c!='.')continue;
        }
        size_t label_len=i-label_start;
        if(label_len==0||label_len>63||auth[label_start]=='-'||auth[i-1]=='-')return -1;
        label_start=i+1;
    }
    if(strlen("/ws")>=sizeof(out->path))return -1;
    memcpy(out->host,auth,host_len+1);memcpy(out->path,"/ws",4);out->port=(uint16_t)port;return 0;
}

int tg_config_read(const char *path,tg_config *out) {
    enum { K_ENABLED=1u<<0,K_URL=1u<<1,K_SECRET=1u<<2,K_IDENTITY=1u<<3,
           K_CA=1u<<4,K_STATUS=1u<<5,K_PORT=1u<<6,K_STATE=1u<<7 };
    FILE *f;char line[2048],state_dir[512]="/opt/d2k/state";unsigned seen=0;int rc=-1;
    int have_identity=0,have_status=0;
    if(!path||!out)return -1;
    memset(out,0,sizeof(*out));out->listen_port=1443;
    if(copy_value(out->identity_path,sizeof(out->identity_path),"/opt/d2k/state/tg.identity")||
       copy_value(out->ca_bundle,sizeof(out->ca_bundle),"/opt/d2k/files/tg-roots.pem")||
       copy_value(out->status_path,sizeof(out->status_path),"/opt/d2k/state/telegram.status"))return -1;
    f=fopen(path,"r");if(!f)return -1;
    while(fgets(line,sizeof(line),f)) {
        if(!strchr(line,'\n')&&!feof(f))goto done;
        char *s=trim(line);if(!*s||*s=='#')continue;
        char *eq=strchr(s,'=');if(!eq)continue;*eq++='\0';char *key=trim(s),*value=trim(eq);
        unsigned bit=0;char *dst=NULL;size_t cap=0;
        if(strcmp(key,"TG_ENABLED")==0)bit=K_ENABLED;
        else if(strcmp(key,"TG_RELAY_URL")==0){bit=K_URL;dst=out->relay_url;cap=sizeof(out->relay_url);}
        else if(strcmp(key,"TG_RELAY_SECRET")==0){bit=K_SECRET;dst=out->relay_secret;cap=sizeof(out->relay_secret);}
        else if(strcmp(key,"TG_IDENTITY")==0){bit=K_IDENTITY;dst=out->identity_path;cap=sizeof(out->identity_path);}
        else if(strcmp(key,"TG_CA_BUNDLE")==0){bit=K_CA;dst=out->ca_bundle;cap=sizeof(out->ca_bundle);}
        else if(strcmp(key,"TG_STATUS")==0){bit=K_STATUS;dst=out->status_path;cap=sizeof(out->status_path);}
        else if(strcmp(key,"TG_PORT")==0)bit=K_PORT;
        else if(strcmp(key,"STATE_DIR")==0){bit=K_STATE;dst=state_dir;cap=sizeof(state_dir);}
        if(!bit)continue;
        if(seen&bit)goto done;seen|=bit;
        if(normalize_shell_value(value)!=0)goto done;
        if(bit==K_ENABLED) {
            if(strcmp(value,"1")==0||strcmp(value,"yes")==0)out->enabled=1;
            else if(strcmp(value,"0")==0||strcmp(value,"no")==0)out->enabled=0;
            else goto done;
        } else if(bit==K_PORT) {
            for(const char *p=value;*p;p++)if(!isdigit((unsigned char)*p))goto done;
            errno=0;unsigned long v=strtoul(value,NULL,10);if(errno||v!=1443)goto done;out->listen_port=(uint16_t)v;
        } else if(!*value||copy_value(dst,cap,value)!=0)goto done;
        if(bit==K_IDENTITY)have_identity=1;
        if(bit==K_STATUS)have_status=1;
    }
    if(ferror(f))goto done;
    if(state_dir[0]!='/')goto done;
    if(!have_identity&&snprintf(out->identity_path,sizeof(out->identity_path),"%s/tg.identity",state_dir)>=(int)sizeof(out->identity_path))goto done;
    if(!have_status&&snprintf(out->status_path,sizeof(out->status_path),"%s/telegram.status",state_dir)>=(int)sizeof(out->status_path))goto done;
    if(out->identity_path[0]!='/'||out->ca_bundle[0]!='/'||out->status_path[0]!='/')goto done;
    rc=0;
done:
    fclose(f);if(rc!=0)tg_config_clean(out);return rc;
}

void tg_config_clean(tg_config *cfg) {
    if(!cfg)return;OPENSSL_cleanse(cfg->relay_secret,sizeof(cfg->relay_secret));
    memset(cfg,0,sizeof(*cfg));
}
