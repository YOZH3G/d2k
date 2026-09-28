#ifndef D2K_TG_QUEUE_INTERNAL_H
#define D2K_TG_QUEUE_INTERNAL_H
#include "tg_streams.h"
void tg_queue_init(tg_byte_queue *queue,size_t cap);
void tg_queue_clear(tg_byte_queue *queue);
int tg_queue_push(tg_byte_queue *queue,const uint8_t *data,size_t len);
int tg_queue_pop(tg_byte_queue *queue,uint8_t *dst,size_t cap,size_t *written);
#endif
