#include <stdio.h>
#include <string.h>
#include "d2k_compose.h"
#include "d2k_quicprobe.h"
static int fails;
#define CHECK(x) do{if(!(x)){printf("FAIL %d: %s\n",__LINE__,#x);fails++;}}while(0)
int main(void){
    d2k_quic_props p={0};p.junk_ahead=p.longer=D2K_PROP_YES;
    char text[16384];
    CHECK(!d2k_quic_compose_plan(NULL,&p,text,sizeof text));
    CHECK(strstr(text,"repeats=1 ") && !strstr(text,"udplen"));
    d2k_quic_arm a={0};a.kind=D2K_QA_TTL;a.original=1;a.len=16;a.copies=2;a.ttl=3;
    CHECK(!d2k_quic_compose_plan(&a,&p,text,sizeof text));
    CHECK(strstr(text,"repeats=2 ") && strstr(text,"ttl=3") && !strstr(text,"udplen"));
    a.kind=D2K_QA_FRAG;a.len=0;a.copies=0;a.ttl=0;a.frag_kind=2;a.frag_survives=D2K_PROP_YES;
    CHECK(!d2k_quic_compose_plan(&a,&p,text,sizeof text));
    CHECK(strstr(text,"ipfrag 2") && !strstr(text,"fake ") && !strstr(text,"udplen"));
    a.kind=D2K_QA_COPIES;a.original=0;a.frag_kind=0;a.len=16;a.copies=6;
    CHECK(d2k_quic_arm_plan(&a,a.bytes,a.len,text,sizeof text)<0);
    CHECK(d2k_quic_compose_plan(&a,&p,text,sizeof text)<0);
    return fails?1:0;
}
