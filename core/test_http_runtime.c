/* HTTP has one bypass engine. Exercise its trial and permanent bindings,
 * using the texts actually installed by httpsearch, not reconstructed plans. */
#define main httpsearch_existing_tests
#include "test_httpsearch.c"
#undef main
#include "../datapath/include/d2k_session.h"
#include "../datapath/include/d2k_wire.h"
#include "../datapath/test_runtime_trace.h"
#include "../datapath/test_nat_stub.h"

static int same_execution(const char *trial_text, const char *permanent_text, int family) {
    const char *host="portal-target.example";
    const char req[]="GET / HTTP/1.1\r\nHost: portal-target.example\r\nAccept: */*\r\n\r\n";
    d2k_conn c={0}; c.family=(uint8_t)family;c.ttl=61;c.window=32000;c.ack=76543;
    c.src_port=htons(53001);c.dst_port=htons(80);c.ip_id=123;
    inet_pton(AF_INET,"192.0.2.1",&c.src_ip);inet_pton(AF_INET,"198.51.100.2",&c.dst_ip);
    inet_pton(AF_INET6,"2001:db8::1",c.src_ip6);inet_pton(AF_INET6,"2001:db8::2",c.dst_ip6);
    d2k_emit e={0};e.kind=D2K_EMIT_PAYLOAD;e.bytes=(const uint8_t *)req;e.len=sizeof req-1;e.seq=10001;
    uint8_t pkt[4096],out[2][65536];d2k_result result[2];
    size_t n=d2k_wire_build(&c,&e,pkt,sizeof pkt);
    if(!n)return 0;
    for(int i=0;i<2;i++) {
        uint8_t tlv[4096];size_t tn=0;char err[200];d2k_plan *p=NULL;
        if(d2k_plan_text_to_tlv(i?permanent_text:trial_text,tlv,sizeof tlv,&tn,err,sizeof err)||
           d2k_plan_load(tlv,tn,&p,err,sizeof err))return 0;
        d2k_session *s=d2k_session_new(64,64);
        if(d2k_plantab_set_name_family(d2k_session_plans(s),(const uint8_t *)host,strlen(host),1,p,
             D2K_PLAN_SHAPE_HTTP,i?0:c.src_port,(uint8_t)family)) {d2k_plan_free(p);d2k_session_free(s);return 0;}
        /* Session must see the actual start of an HTTP stream. The wire
           helper builds data packets; turn an empty one into a valid SYN. */
        uint8_t syn[256];d2k_emit se=e;se.len=0;se.seq=e.seq-1;
        size_t sn=d2k_wire_build(&c,&se,syn,sizeof syn);size_t th=family==6?40:20;
        syn[th+13]=2;
        unsigned sum=((unsigned)syn[th+16]<<8|syn[th+17])+0x16u;
        sum=(sum&65535u)+(sum>>16);syn[th+16]=(uint8_t)(sum>>8);syn[th+17]=(uint8_t)sum;
        CHECK(sn && d2k_wire_tcp_checksum_ok(syn,sn),"valid SYN context");
        if(i)d2k_session_packet(s,syn,sn,900,out[i],sizeof out[i],&result[i]);
        else d2k_session_packet_probe(s,syn,sn,900,out[i],sizeof out[i],&result[i]);
        if(i)d2k_session_packet(s,pkt,n,1000,out[i],sizeof out[i],&result[i]);
        else d2k_session_packet_probe(s,pkt,n,1000,out[i],sizeof out[i],&result[i]);
        d2k_session_free(s);
    }
    if(!result[0].applied||!result[1].applied||!result[0].n_out||result[0].n_out!=result[1].n_out)return 0;
    for(size_t i=0;i<result[0].n_out;i++) {
        d2k_test_packet a={out[0]+result[0].out[i].off,result[0].out[i].len,result[0].out[i].delay_us};
        d2k_test_packet b={out[1]+result[1].out[i].off,result[1].out[i].len,result[1].out[i].delay_us};
        if(!d2k_test_packet_equal(&a,&b))return 0;
    }
    return 1;
}
static void alter_program(char *text) {
    char *cut=strstr(text,"split sni_middle +0");
    if(cut)cut[strlen("split sni_middle +")]='1';
    else {char *fake=strstr(text,"repeats=1");if(fake)fake[8]='2';}
}
int main(int argc, char **argv) {
    D2K_TEST_NAT_NO_TABLE();
    int force_divergence=argc==2 && !strcmp(argv[1],"--diverge");
    for(int family=4;family<=6;family+=2)for(int answer=0;answer<3;answer++) {
        fake f={0};d2k_hs_ops ops=ops_of(&f);d2k_httpsearch *hs=d2k_httpsearch_new(&ops);int64_t now=1;
        d2k_httpsearch_portal(hs,"portal-target.example",(uint8_t)family,IP,now);base_injected(hs,&f,&now);
        for(int miss=0;miss<answer;miss++)trial(hs,&f,&now,1,D2K_HS_INJECTED);
        trial(hs,&f,&now,1,D2K_HS_REAL);trial(hs,&f,&now,1,D2K_HS_REAL);
        CHECK(f.set_plan_n==1,"confirmed property exports plan");
        if(force_divergence)alter_program(f.last_plan);
        CHECK(same_execution(f.last_probe_plan,f.last_plan,family),"trial/permanent runtime packet mismatch");
        char altered[2048];snprintf(altered,sizeof altered,"%s",f.last_plan);
        alter_program(altered);
        CHECK(!same_execution(f.last_probe_plan,altered,family),"gate accepted changed runtime bytes");
        d2k_httpsearch_free(hs);
    }
    if(fails){printf("HTTP runtime: FAIL %d\n",fails);return 1;}
    puts("HTTP runtime: IPv4/IPv6 trial == permanent; deliberate divergence rejected");return 0;
}
