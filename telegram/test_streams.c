#define _DARWIN_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "tg_listener.h"
#include "tg_streams.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

static void test_original_dst_and_self_dial(void) {
    uint8_t raw[16]={0}; uint8_t ip[4]; uint16_t port;
    uint16_t family=AF_INET, net_port=htons(443);
    memcpy(raw,&family,sizeof(family)); memcpy(raw+2,&net_port,sizeof(net_port));
    raw[4]=149;raw[5]=154;raw[6]=167;raw[7]=51;
    assert(tg_listener_decode_original_dst(raw,sizeof(raw),&port,ip)==0);
    assert(port==443 && ip[0]==149 && ip[3]==51);
    uint16_t ports[]={1443,1444};
    assert(tg_listener_is_self_dial(ip,1443,ports,2));
    const uint8_t private_ip[4]={192,168,1,1};
    assert(tg_listener_is_self_dial(private_ip,443,ports,2));
    const uint8_t public_ip[4]={149,154,167,51};
    assert(!tg_listener_is_self_dial(public_ip,443,ports,2));
    family=AF_INET6; memcpy(raw,&family,sizeof(family));
    assert(tg_listener_decode_original_dst(raw,sizeof(raw),&port,ip)!=0);
}

static void test_queue_bounds_isolation_and_close_order(void) {
    tg_stream_table table; tg_stream_table_init(&table,1024,160,100);
    tg_stream *slow=tg_stream_open(&table),*fast=tg_stream_open(&table);
    assert(slow && fast && slow->id!=fast->id);
    uint8_t data[80]; for(size_t i=0;i<sizeof(data);i++)data[i]=(uint8_t)i;
    assert(tg_stream_queue_remote_data(slow,data,sizeof(data))==0);
    assert(tg_stream_queue_remote_data(slow,data,sizeof(data))==0);
    assert(tg_stream_queue_remote_data(slow,data,1)!=0);
    assert(tg_stream_queue_remote_data(fast,(const uint8_t *)"ok",2)!=0);
    assert(tg_stream_remote_close(slow)==0 && !tg_stream_ready_to_close(slow));
    uint8_t out[160]; size_t n=0;
    assert(tg_stream_pop_local(slow,out,60,&n)==0 && n==60);
    assert(memcmp(out,data,60)==0);
    assert(tg_stream_pop_local(slow,out,sizeof(out),&n)==0 && n==20);
    assert(memcmp(out,data+60,20)==0);
    assert(tg_stream_pop_local(slow,out+20,sizeof(out)-20,&n)==0 && n==80);
    assert(memcmp(out+20,data,80)==0);
    assert(tg_stream_ready_to_close(slow));
    assert(tg_stream_queue_remote_data(fast,(const uint8_t *)"ok",2)==0);
    assert(tg_stream_pop_local(fast,out,sizeof(out),&n)==0 && n==2 && memcmp(out,"ok",2)==0);
    tg_stream_table_destroy(&table);
}

static void test_connect_slots_credit_and_window(void) {
    tg_stream_table table; tg_stream_table_init(&table,1024,1024,20);
    tg_stream *s=tg_stream_open(&table); assert(s);
    assert(tg_stream_connect_begin(&table,s)==0);
    assert(tg_stream_connect_ok(&table,s,0)==0);
    assert(tg_stream_send_data(s,(const uint8_t *)"x",1)==TG_STREAM_NO_CREDIT);
    tg_stream_grant_credit(s,120);
    assert(tg_stream_send_data(s,(const uint8_t *)"abc",3)==0 && s->send_credit==117);
    assert(tg_stream_queue_remote_data(s,(const uint8_t *)"123456",6)==0);
    uint8_t data[8]; size_t n; uint32_t window_credit=0;
    assert(tg_stream_pop_local(s,data,sizeof(data),&n)==0 && n==6);
    assert(tg_stream_local_write_complete(s,(uint32_t)n,&window_credit)==0 && window_credit==0);
    assert(tg_stream_queue_remote_data(s,(const uint8_t *)"7890123456",10)==0);
    assert(tg_stream_pop_local(s,data,sizeof(data),&n)==0 && n==8);
    assert(tg_stream_local_write_complete(s,(uint32_t)n,&window_credit)==0 && window_credit==14);
    tg_stream_table_destroy(&table);
}

static void test_connect_limit_and_session_loss(void) {
    tg_stream_table table; tg_stream_table_init(&table,1024,4096,0);
    tg_stream *streams[7];
    for(size_t i=0;i<7;i++){streams[i]=tg_stream_open(&table);assert(streams[i]);}
    for(size_t i=0;i<6;i++)assert(tg_stream_connect_begin(&table,streams[i])==0);
    assert(tg_stream_connect_begin(&table,streams[6])==TG_STREAM_CONNECT_LIMITED);
    tg_stream_table_session_lost(&table);
    assert(tg_stream_table_count(&table)==0);
    tg_stream_table_destroy(&table);
}

int main(void) {
    test_original_dst_and_self_dial(); test_queue_bounds_isolation_and_close_order();
    test_connect_slots_credit_and_window(); test_connect_limit_and_session_loss();
    puts("stream tests: ok"); return 0;
}
