/* Incremental request framing shared by application and live observation.
 * No header/value buffer: large Cookie fields cost no additional flow memory.
 * Call only at an independently recognized request start. */
#ifndef D2K_HTTP_REQUEST_STREAM_H
#define D2K_HTTP_REQUEST_STREAM_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef struct {
    uint32_t start, next, head_len, end;
    uint64_t length;
    uint8_t first, cr, line, value, field, name_len;
    uint8_t cl_seen, digits, trailing, hosts;
    uint8_t invalid, header_done, past_end;
    char name[18];
} d2k_http_request_stream;

static inline void d2k_http_request_stream_init(d2k_http_request_stream *s,uint32_t seq) {
    memset(s,0,sizeof *s);s->start=s->next=seq;s->first=1;
}
static inline void d2k_http_request_stream_line(d2k_http_request_stream *s) {
    if(s->first) s->first=0;
    else if(!s->line) {
        uint64_t end=(uint64_t)(s->next-s->start)+s->length;
        if(s->hosts!=1 || end>0x7fffffffu) {s->invalid=1;return;}
        s->header_done=1;s->head_len=s->next-s->start;s->end=s->start+(uint32_t)end;
    } else if(!s->value || (s->field==1 && !s->digits)) s->invalid=1;
    s->line=s->value=s->field=s->name_len=s->digits=s->trailing=0;
}
static inline void d2k_http_request_stream_feed(d2k_http_request_stream *s,
                                               uint32_t seq,const uint8_t *p,size_t n) {
    if(s->invalid || !n)return;
    if(n>0x7fffffffu) {s->invalid=1;return;}
    if(seq!=s->next) {
        /* Only wholly old data is ignorable. Missing bytes and partial
         * overlap cannot supply a trustworthy request boundary. */
        if((int32_t)(seq-s->next)<0 && (int32_t)(seq+(uint32_t)n-s->next)<=0)return;
        s->invalid=1;return;
    }
    for(size_t i=0;i<n;i++) {
        uint8_t c=p[i];s->next++;
        if((uint32_t)(s->next-s->start)>0x7fffffffu) {s->invalid=1;return;}
        if(s->header_done) {
            if((int32_t)(s->next-s->end)>0)s->past_end=1;
            continue;
        }
        if(s->cr) {
            s->cr=0;
            if(c!='\n') {s->invalid=1;return;}
            d2k_http_request_stream_line(s);
            if(s->invalid)return;
            continue;
        }
        if(c=='\r') {s->cr=1;continue;}
        if(c=='\n' || c==0x7f || (c<0x20 && c!='\t')) {s->invalid=1;return;}
        s->line=1;
        if(s->first)continue;
        if(!s->value) {
            if(c==':') {
                s->value=1;
                if(s->name_len==14 && !memcmp(s->name,"content-length",14)) {
                    if(s->cl_seen++) {s->invalid=1;return;}
                    s->field=1;
                } else if((s->name_len==17 && !memcmp(s->name,"transfer-encoding",17)) ||
                          (s->name_len==7 && !memcmp(s->name,"upgrade",7))) {
                    s->invalid=1;return;
                } else if(s->name_len==4 && !memcmp(s->name,"host",4)) {
                    if(s->hosts++) {s->invalid=1;return;}
                } else if(!s->name_len) {s->invalid=1;return;}
            } else {
                /* Reject whitespace before colon and obsolete folded lines. */
                if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||
                     strchr("!#$%&'*+-.^_`|~",c))) {s->invalid=1;return;}
                if(s->name_len<sizeof s->name) {
                    s->name[s->name_len++]=(char)(c>='A'&&c<='Z'?c+32:c);
                }
            }
        } else if(s->field==1) {
            if(c==' ' || c=='\t') {if(s->digits)s->trailing=1;}
            else if(c>='0' && c<='9' && !s->trailing && s->digits<10) {
                s->digits++;s->length=s->length*10u+(uint64_t)(c-'0');
            } else {s->invalid=1;return;}
        }
    }
}
#endif
