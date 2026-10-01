#ifndef D2K_TG_STREAMS_H
#define D2K_TG_STREAMS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define TG_STREAM_CONNECT_LIMIT 6
#define TG_STREAM_NO_CREDIT (-2)
#define TG_STREAM_CONNECT_LIMITED (-3)
#define TG_STREAM_MAX 1024
#define TG_STREAM_IDLE_TIMEOUT_MS (15u*60u*1000u)
#define TG_STREAM_MEMORY_LIMIT (16u*1024u*1024u)

typedef struct tg_queue_node tg_queue_node;
typedef struct { tg_queue_node *head,*tail; size_t bytes,cap,memory_bytes; int closed,finished; } tg_byte_queue;
typedef struct tg_stream tg_stream;
typedef struct {
    tg_stream **items; size_t count,capacity,queue_cap,queued_bytes; uint32_t window;
    uint16_t next_id; size_t connecting;
    /* Requested storage, including the table, items, streams and queue nodes.
     * Separate from remaining payload; allocator metadata is not included. */
    size_t memory_bytes,memory_cap;
} tg_stream_table;

struct tg_stream {
    tg_stream_table *table;
    uint16_t id; int connect_pending,connected,remote_closed,local_eof,session_lost;
    uint64_t send_credit,recv_unacked,recv_ack_pending,last_activity_ms;
    uint32_t window;
    int fd; uint8_t target_ipv4[4]; uint16_t target_port; uint64_t connect_deadline_ms;
    uint8_t local_pending[16384]; size_t local_pending_len,local_pending_offset;
    tg_byte_queue to_local;
};

void tg_stream_table_init(tg_stream_table *table,size_t max_streams,size_t queue_cap,uint32_t window);
void tg_stream_table_destroy(tg_stream_table *table);
tg_stream *tg_stream_open(tg_stream_table *table);
tg_stream *tg_stream_find(tg_stream_table *table,uint16_t id);
void tg_stream_remove(tg_stream_table *table,tg_stream *stream);
size_t tg_stream_table_count(const tg_stream_table *table);
int tg_stream_connect_begin(tg_stream_table *table,tg_stream *stream);
int tg_stream_connect_ok(tg_stream_table *table,tg_stream *stream,uint32_t initial_credit);
void tg_stream_grant_credit(tg_stream *stream,uint32_t credit);
void tg_stream_connect_fail(tg_stream_table *table,tg_stream *stream);
int tg_stream_send_data(tg_stream *stream,const uint8_t *data,size_t len);
int tg_stream_queue_remote_data(tg_stream *stream,const uint8_t *data,size_t len);
int tg_stream_pop_local(tg_stream *stream,uint8_t *dst,size_t cap,size_t *written);
int tg_stream_local_write_complete(tg_stream *stream,uint32_t written,uint32_t *window_credit);
int tg_stream_remote_close(tg_stream *stream);
int tg_stream_ready_to_close(const tg_stream *stream);
void tg_stream_local_eof(tg_stream *stream);
void tg_stream_table_session_lost(tg_stream_table *table);

#endif
