#include "tg_streams.h"
#include "queue_internal.h"

#include <stdlib.h>
#include <string.h>

struct tg_queue_node { struct tg_queue_node *next; uint8_t *data; size_t len,offset; };

void tg_queue_init(tg_byte_queue *q,size_t cap) { memset(q,0,sizeof(*q)); q->cap=cap; }
void tg_queue_clear(tg_byte_queue *q) {
    tg_queue_node *n=q->head;
    while(n){tg_queue_node *next=n->next;free(n->data);free(n);n=next;}
    q->head=q->tail=NULL;q->bytes=0;q->memory_bytes=0;q->closed=1;
}
int tg_queue_push(tg_byte_queue *q,const uint8_t *data,size_t len,size_t memory_available) {
    if(!q||(!data&&len)||q->closed||q->finished||q->bytes>q->cap||len>q->cap-q->bytes)return -1;
    if(len==0)return 0;
    if(len>SIZE_MAX-sizeof(tg_queue_node)||len+sizeof(tg_queue_node)>memory_available)return -1;
    tg_queue_node *n=calloc(1,sizeof(*n)); if(!n)return -1;
    n->data=malloc(len); if(!n->data){free(n);return -1;}
    memcpy(n->data,data,len);n->len=len;
    if(q->tail) { q->tail->next=n; }
    else { q->head=n; }
    q->tail=n;q->bytes+=len;
    q->memory_bytes+=len+sizeof(*n);return 0;
}
int tg_queue_pop(tg_byte_queue *q,uint8_t *dst,size_t cap,size_t *written) {
    if(!q||!dst||!written)return -1;
    *written=0; tg_queue_node *n=q->head; if(!n)return 0;
    size_t count=n->len-n->offset;if(count>cap)count=cap;
    memcpy(dst,n->data+n->offset,count);n->offset+=count;q->bytes-=count;*written=count;
    if(n->offset==n->len){q->head=n->next;if(!q->head)q->tail=NULL;
        q->memory_bytes-=n->len+sizeof(*n);free(n->data);free(n);}
    return 0;
}
