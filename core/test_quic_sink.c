#define __APPLE_USE_RFC_3542
/* Keep the syscall capture and real Session comparator in one reusable gate. */
#define main udp_runtime_gate_main
#include "test_udp_runtime.c"
#undef main
#define getsockname mock_local
#define getpeername mock_peer
#define getsockopt mock_get
#define setsockopt mock_set
#define send mock_send
#define nanosleep mock_sleep
#include "quicprobe.c"
#undef getsockname
#undef getpeername
#undef getsockopt
#undef setsockopt
#undef send
#undef nanosleep
int main(void){
    ctx(4);current_ttl=47;sent_count=0;uint8_t prefix[16]={0},bad[32]={0};
    d2k_quic_arm_question q={.blob=prefix,.blob_len=sizeof prefix,.copies=11,.split=1};
    qp_arm_action a={0};a.q=&q;a.family=AF_INET;
    /* In the former sender fake11 escaped BEFORE the split was validated. */
    CHECK(qp_arm_first_send(42,bad,sizeof bad,&a)<0);
    CHECK(sent_count==0 && !a.initial_out);
    uint8_t initial[4096];size_t n=0;CHECK(!d2k_quic_probe_initial("example.com",initial,sizeof initial,&n));
    q.split=0;q.ttl=3;q.copies=2;fail_send=1;current_ttl=47;
    CHECK(qp_arm_first_send(42,initial,n,&a)<0);
    CHECK(current_ttl==47);fail_send=0;
    for(int family=4;family<=6;family+=2){
        ctx(family);current_ttl=47;sent_count=lower_count=elapsed=0;
        CHECK(qp_arm_first_send(42,initial,n,&a)==1);
        CHECK(sent_count==3 && sent[0].ttl==3 && sent[1].ttl==3 && sent[2].ttl==47);
        CHECK(sent[2].len==n && !memcmp(sent[2].bytes,initial,n));
        CHECK(current_ttl==47 && elapsed==0);
    }
    printf("QUIC actual first-send sink: %d failures\n",fails);return fails?1:0;
}
