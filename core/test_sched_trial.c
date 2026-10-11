/* Candidate execution identity before and after the verifier result.
 * Reuse the existing scheduler harness; all network answers are local stubs. */
#define main scheduler_existing_main
#include "test_sched.c"
#undef main

int main(void) {
    d2k_sched_vol_hook=stub_vol;d2k_sched_tcp_hook=stub_tcp;
    d2k_sched_quic_hook=stub_quic;d2k_sched_ver_hook=stub_ver;
    d2k_sched_rx_ver_hook=stub_ver;d2k_sched_rx_gzip_ver_hook=stub_ver;
    d2k_sched_quic_path_ver_hook=stub_quic_path_ver;
    d2k_sched_mark_hook=stub_mark;d2k_sched_spawn_hook=stub_spawn;
    d2k_sched_cpu_hook=stub_cpu;d2k_sched_mem_hook=stub_mem;d2k_sched_ct_hook=stub_ct;
    int sv[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,sv),"trial control socketpair");
    drain_fd=sv[1];fcntl(drain_fd,F_SETFL,fcntl(drain_fd,F_GETFL,0)|O_NONBLOCK);
    g_server_port=443;
    for(int family=4;family<=6;family+=2) for(int kind=0;kind<3;kind++) for(int late=0;late<2;late++) for(int proof=0;proof<3;proof++) {
        d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,sv[0],0x2d);
        const char *name="trial.example";uint8_t transport=kind?17:6;
        saidbuf[0]=0;forget_sent();d2k_sched_set_say(s,collect_say,NULL);
        tcp_answer=quic_answer=D2K_V_PREFIX;ver_answer=D2K_VER_APPLICATION;
        ver_fail_first=ver_calls=0;ver_answer_port=40550;
        const uint8_t local[4]={192,168,1,67};memcpy(ver_local_ip4,local,4);
        d2k_ev h=ev_hello(transport,40550,name);h.family=(uint8_t)family;
        if(family==6) {inet_pton(AF_INET6,"::1",h.low_ip);inet_pton(AF_INET6,"2001:db8::2",h.high_ip);}
        if(kind!=2)d2k_sched_event(s,&h);
        d2k_ev suspect=h;suspect.kind=D2K_EV_SUSPECT;suspect.code=D2K_SUSPECT_RST_CUT;
        suspect.name[0]=0;d2k_sched_event(s,&suspect);
        if(kind==1) {d2k_ev shape;CHECK(!quic_shape(&shape,name),"QUIC shape fixture");shape.family=(uint8_t)family;d2k_sched_event(s,&shape);}
        spin_until_installed(s);
        uint8_t id[16]={0};d2k_ev event=ev_applied(transport,40550),ack;
        event.family=(uint8_t)family;memcpy(event.low_ip,h.low_ip,16);memcpy(event.high_ip,h.high_ip,16);
        if(kind==2) {
            uint8_t endpoint[38]={0};int found=0;
            for(size_t off=0;off+6<=sent_len;) {
                const uint8_t *p=sentbuf+off;
                uint32_t n=(uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];
                if(n<2||n>sent_len-off-4)break;
                if((((unsigned)p[4]<<8)|p[5])==D2K_CMD_SET_ADDR_PROBE&&n>=2+38+16) {
                    memcpy(endpoint,p+6,38);memcpy(id,p+6+38,16);found=1;
                }
                off+=4+n;
            }
            CHECK(found,"address trial command");
            memcpy(ver_local_ip4,endpoint+1,4);
            ver_answer_port=(uint16_t)((unsigned)endpoint[33]<<8|endpoint[34]);
            memcpy(event.high_ip,endpoint+1,16);event.high_port=ver_answer_port;
            ack=addr_probe_ack(id,1,D2K_ACK_OK);
        } else {
            CHECK(name_probe_trial(name,id),"name trial command");
            ack=name_probe_ack(id,1,D2K_ACK_OK);
        }
        memcpy(event.trial_id,id,16);
        if(proof==0)memset(event.trial_id,0,16);
        if(proof==1)event.trial_id[0]^=1;
        if(!late)d2k_sched_event(s,&event);
        d2k_sched_event(s,&ack);
        settle(s);
        if(late){d2k_sched_event(s,&event);spin(s,40);}
        if((total_bindings(&cat)>0)!=(proof==2))
            printf("identity case family=%d kind=%d late=%d proof=%d bindings=%zu\n",family,kind,late,proof,total_bindings(&cat));
        CHECK((total_bindings(&cat)>0)==(proof==2),"only this trial may confirm its candidate");
        d2k_sched_free(s);d2k_catalog_free(&cat);
    }
    close(sv[0]);close(sv[1]);
    printf("candidate trial identity: %d failures\n",fails);return fails?1:0;
}
