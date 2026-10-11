/* Bounded streaming HTTP/1 response framing, no I/O and no packet production.
 * Unsupported/ambiguous framing is unknown, never a complete response.
 * A caller must supply contiguous, deduplicated TCP bytes and genuine FIN. */
#ifndef D2K_HTTP_RESPONSE_H
#define D2K_HTTP_RESPONSE_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>

enum { D2K_HR_HEADER, D2K_HR_FIXED, D2K_HR_SIZE, D2K_HR_CHUNK,
       D2K_HR_CR, D2K_HR_LF, D2K_HR_TRAILER, D2K_HR_CLOSE };
typedef struct {
    char head[8192], line[512];
    size_t head_len, line_len;
    uint64_t remaining, body_bytes;
    unsigned status;
    int state, head_only, header_done, complete, invalid, interim;
} d2k_http_response;

static inline int d2k_hr_decimal(const char *p, size_t n, uint64_t *v) {
    if(!n)return 0;
    *v=0;
    for(size_t i=0;i<n;i++) {
        if(p[i]<'0'||p[i]>'9'||*v>(UINT64_MAX-(unsigned)(p[i]-'0'))/10)return 0;
        *v=*v*10+(unsigned)(p[i]-'0');
    }
    return 1;
}

static inline int d2k_hr_token(unsigned char c) {
    return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||
        (c && strchr("!#$%&'*+-.^_`|~",c)!=NULL);
}
static inline int d2k_hr_field(const char *p,size_t n) {
    const char *colon=memchr(p,':',n);
    if(!colon || colon==p)return 0;
    for(const char *q=p;q<colon;q++)if(!d2k_hr_token((unsigned char)*q))return 0;
    for(const char *q=colon+1;q<p+n;q++)
        if(((unsigned char)*q<32 && *q!='\t') || *q==127)return 0;
    return 1;
}
static inline int d2k_hr_extensions(const char *p,size_t n) {
    size_t i=0;
    while(i<n) {
        while(i<n && (p[i]==' '||p[i]=='\t'))i++;
        if(i==n || p[i++]!=';')return 0;
        while(i<n && (p[i]==' '||p[i]=='\t'))i++;
        size_t start=i;while(i<n && d2k_hr_token((unsigned char)p[i]))i++;
        if(i==start)return 0;
        while(i<n && (p[i]==' '||p[i]=='\t'))i++;
        if(i<n && p[i]=='=') {
            i++;while(i<n && (p[i]==' '||p[i]=='\t'))i++;
            if(i<n && p[i]=='"') {
                i++;int closed=0;
                while(i<n) {
                    unsigned char c=(unsigned char)p[i++];
                    if(c=='"') {closed=1;break;}
                    if(c=='\\') {if(i==n)return 0;c=(unsigned char)p[i++];}
                    if((c<32 && c!='\t') || c==127)return 0;
                }
                if(!closed)return 0;
            } else {
                start=i;while(i<n && d2k_hr_token((unsigned char)p[i]))i++;
                if(start==i)return 0;
            }
        }
    }
    return 1;
}

static inline int d2k_hr_headers(d2k_http_response *r) {
    const char *p=r->head,*end=p+r->head_len,*e=strstr(p,"\r\n");
    if(!e || e-p<12 || (memcmp(p,"HTTP/1.1 ",9)&&memcmp(p,"HTTP/1.0 ",9)) ||
       p[9]<'1'||p[9]>'5'||p[10]<'0'||p[10]>'9'||p[11]<'0'||p[11]>'9'||
       (e-p>12 && p[12]!=' '))return 0;
    r->status=(unsigned)(p[9]-'0')*100+(unsigned)(p[10]-'0')*10+(unsigned)(p[11]-'0');
    int cl=0,te=0;uint64_t length=0;
    p=e+2;
    while(p<end-2) {
        e=strstr(p,"\r\n");if(!e || e==p)return 0;
        const char *colon=memchr(p,':',(size_t)(e-p));
        if(!d2k_hr_field(p,(size_t)(e-p)))return 0;
        const char *v=colon+1,*ve=e;
        while(v<ve && (*v==' '||*v=='\t'))v++;
        while(ve>v && (ve[-1]==' '||ve[-1]=='\t'))ve--;
        if(colon-p==14 && !strncasecmp(p,"Content-Length",14)) {
            if(cl++ || !d2k_hr_decimal(v,(size_t)(ve-v),&length))return 0;
        } else if(colon-p==17 && !strncasecmp(p,"Transfer-Encoding",17)) {
            if(te++ || ve-v!=7 || strncasecmp(v,"chunked",7))return 0;
        }
        p=e+2;
    }
    if(cl && te)return 0;
    if(r->status<200) {
        if(r->status==101 || cl || te)return 0;
        r->interim=1;r->head_len=0;r->head[0]=0;return 1; /* interim, final header still needed */
    }
    r->header_done=1;
    if(r->head_only || r->status==204 || r->status==304)r->complete=1;
    else if(te)r->state=D2K_HR_SIZE;
    else if(cl) {r->state=D2K_HR_FIXED;r->remaining=length;r->complete=!length;}
    else r->state=D2K_HR_CLOSE;
    return 1;
}

static inline void d2k_http_response_feed(d2k_http_response *r,const uint8_t *p,size_t n,int fin) {
    if(r->invalid)return;
    for(size_t i=0;i<n;i++) {
        unsigned char c=p[i];
        if(r->complete) {r->invalid=1;break;} /* unsolicited/pipelined bytes */
        if(r->state==D2K_HR_HEADER) {
            if(!c || (c<32 && c!='\r' && c!='\n' && c!='\t') || c==127 ||
               r->head_len+1>=sizeof r->head) {r->invalid=1;break;}
            if((c=='\n' && (!r->head_len || r->head[r->head_len-1]!='\r')) ||
               (r->head_len && r->head[r->head_len-1]=='\r' && c!='\n')) {r->invalid=1;break;}
            r->head[r->head_len++]=(char)c;r->head[r->head_len]=0;
            if(r->head_len>=4 && !memcmp(r->head+r->head_len-4,"\r\n\r\n",4) && !d2k_hr_headers(r)) {r->invalid=1;break;}
        } else if(r->state==D2K_HR_FIXED || r->state==D2K_HR_CHUNK || r->state==D2K_HR_CLOSE) {
            if(r->body_bytes==UINT64_MAX) {r->invalid=1;break;}
            r->body_bytes++;
            if(r->state!=D2K_HR_CLOSE && !--r->remaining) {
                if(r->state==D2K_HR_FIXED)r->complete=1;else r->state=D2K_HR_CR;
            }
        } else if(r->state==D2K_HR_CR) {
            if(c!='\r') {r->invalid=1;break;}r->state=D2K_HR_LF;
        } else if(r->state==D2K_HR_LF) {
            if(c!='\n') {r->invalid=1;break;}r->state=D2K_HR_SIZE;
        } else {
            if(!c || (c<32 && c!='\r' && c!='\n' && c!='\t') || c==127 ||
               r->line_len+1>=sizeof r->line) {r->invalid=1;break;}
            if((c=='\n' && (!r->line_len || r->line[r->line_len-1]!='\r')) ||
               (r->line_len && r->line[r->line_len-1]=='\r' && c!='\n')) {r->invalid=1;break;}
            r->line[r->line_len++]=(char)c;r->line[r->line_len]=0;
            if(c!='\n')continue;
            if(r->line_len<2 || r->line[r->line_len-2]!='\r') {r->invalid=1;break;}
            size_t len=r->line_len-2;
            if(r->state==D2K_HR_TRAILER) {
                if(!len)r->complete=1;
                else if(!d2k_hr_field(r->line,len)) {r->invalid=1;break;}
            } else {
                uint64_t value=0;size_t digits=0;
                for(;digits<len && r->line[digits]!=';' && r->line[digits]!=' ' && r->line[digits]!='\t';digits++) {
                    unsigned char x=(unsigned char)r->line[digits];unsigned d;
                    if(x>='0'&&x<='9')d=x-'0';else if(x>='a'&&x<='f')d=x-'a'+10;
                    else if(x>='A'&&x<='F')d=x-'A'+10;else {r->invalid=1;break;}
                    if(value>(UINT64_MAX-d)/16) {r->invalid=1;break;}value=value*16+d;
                }
                if(!digits || r->invalid || !d2k_hr_extensions(r->line+digits,len-digits)) {r->invalid=1;break;}
                r->remaining=value;r->state=value?D2K_HR_CHUNK:D2K_HR_TRAILER;
            }
            r->line_len=0;
        }
    }
    if(fin && !r->invalid) {
        if(r->state==D2K_HR_CLOSE && r->header_done)r->complete=1;
        else if(!r->complete)r->invalid=1;
    }
    if(r->invalid)r->complete=0;
}
#endif
