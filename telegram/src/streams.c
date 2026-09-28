#include "tg_streams.h"
#include "queue_internal.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void tg_stream_table_init(tg_stream_table *t,size_t max_streams,size_t queue_cap,uint32_t window) {
    if(!t)return;
    memset(t,0,sizeof(*t));
    if(max_streams>TG_STREAM_MAX)max_streams=TG_STREAM_MAX;
    t->capacity=max_streams;t->queue_cap=queue_cap;t->window=window;
    t->items=calloc(max_streams,sizeof(*t->items));
}

static void stream_free(tg_stream *s){if(s){if(s->table&&s->table->queued_bytes>=s->to_local.bytes)s->table->queued_bytes-=s->to_local.bytes;if(s->fd>=0)close(s->fd);tg_queue_clear(&s->to_local);free(s);}}
void tg_stream_table_destroy(tg_stream_table *t) {
    if(!t)return;
    for(size_t i=0;i<t->capacity;i++)stream_free(t->items?t->items[i]:NULL);
    free(t->items);memset(t,0,sizeof(*t));
}
tg_stream *tg_stream_open(tg_stream_table *t) {
    if(!t||!t->items||t->count>=t->capacity)return NULL;
    uint16_t id=0;
    for(size_t tries=0;tries<UINT16_MAX;tries++) {
        t->next_id=(uint16_t)(t->next_id==UINT16_MAX?1:t->next_id+1);
        if(t->next_id==0)t->next_id=1;
        if(!tg_stream_find(t,t->next_id)){id=t->next_id;break;}
    }
    if(!id)return NULL;
    tg_stream *s=calloc(1,sizeof(*s));
    if(!s)return NULL;
    s->id=id;s->fd=-1;s->window=t->window;s->table=t;tg_queue_init(&s->to_local,t->queue_cap);
    for(size_t i=0;i<t->capacity;i++)if(!t->items[i]){t->items[i]=s;t->count++;return s;}
    stream_free(s);return NULL;
}
tg_stream *tg_stream_find(tg_stream_table *t,uint16_t id){
    if(!t||!t->items)return NULL;
    for(size_t i=0;i<t->capacity;i++)if(t->items[i]&&t->items[i]->id==id)return t->items[i];
    return NULL;
}
void tg_stream_remove(tg_stream_table *t,tg_stream *s){
    if(!t||!s)return;
    for(size_t i=0;i<t->capacity;i++)if(t->items[i]==s){
        if(s->connect_pending&&t->connecting)t->connecting--;
        t->items[i]=NULL;t->count--;stream_free(s);return;
    }
}
size_t tg_stream_table_count(const tg_stream_table *t){return t?t->count:0;}
int tg_stream_connect_begin(tg_stream_table *t,tg_stream *s){
    if(!t||!s||s->connect_pending||s->connected)return -1;
    if(t->connecting>=TG_STREAM_CONNECT_LIMIT)return TG_STREAM_CONNECT_LIMITED;
    s->connect_pending=1;t->connecting++;return 0;
}
int tg_stream_connect_ok(tg_stream_table *t,tg_stream *s,uint32_t credit){
    if(!t||!s||!s->connect_pending)return -1;
    s->connect_pending=0;if(t->connecting)t->connecting--;
    s->connected=1;s->send_credit=credit;return 0;
}
void tg_stream_grant_credit(tg_stream *s,uint32_t credit){if(s&&UINT64_MAX-s->send_credit>=credit)s->send_credit+=credit;}
void tg_stream_connect_fail(tg_stream_table *t,tg_stream *s){
    if(!t||!s)return;
    if(s->connect_pending&&t->connecting)t->connecting--;
    s->connect_pending=0;s->remote_closed=1;s->to_local.finished=1;
}
int tg_stream_send_data(tg_stream *s,const uint8_t *data,size_t len){
    if(!s||(!data&&len)||!s->connected||s->remote_closed)return -1;
    if(len>s->send_credit)return TG_STREAM_NO_CREDIT;s->send_credit-=len;return 0;
}
int tg_stream_queue_remote_data(tg_stream *s,const uint8_t *data,size_t len){
    if(!s||s->remote_closed||s->session_lost||!s->table)return -1;
    if(len>s->table->queue_cap-s->table->queued_bytes)return -1;
    if(tg_queue_push(&s->to_local,data,len)!=0)return -1;
    s->table->queued_bytes+=len;s->recv_unacked+=len;return 0;
}
int tg_stream_pop_local(tg_stream *s,uint8_t *dst,size_t cap,size_t *written){
    if(!s)return -1;int rc=tg_queue_pop(&s->to_local,dst,cap,written);
    if(rc==0&&s->table&&s->table->queued_bytes>=*written)s->table->queued_bytes-=*written;
    return rc;
}
int tg_stream_local_write_complete(tg_stream *s,uint32_t written,uint32_t *credit){
    if(!s||!credit||written>s->recv_unacked)return -1;
    *credit=0;s->recv_unacked-=written;s->recv_ack_pending+=written;
    uint32_t threshold=s->window/2;if(threshold==0&&s->window)threshold=1;
    if(threshold&&s->recv_ack_pending>=threshold){
        if(s->recv_ack_pending>UINT32_MAX)return -1;
        *credit=(uint32_t)s->recv_ack_pending;s->recv_ack_pending=0;
    }
    return 0;
}
int tg_stream_remote_close(tg_stream *s){if(!s)return -1;s->remote_closed=1;s->to_local.finished=1;return 0;}
int tg_stream_ready_to_close(const tg_stream *s){return s&&s->remote_closed&&s->to_local.bytes==0;}
void tg_stream_local_eof(tg_stream *s){if(s)s->local_eof=1;}
void tg_stream_table_session_lost(tg_stream_table *t){
    if(!t||!t->items)return;
    for(size_t i=0;i<t->capacity;i++)if(t->items[i]){
        t->items[i]->session_lost=1;stream_free(t->items[i]);t->items[i]=NULL;
    }
    t->count=0;t->connecting=0;
}
