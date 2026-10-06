#define _POSIX_C_SOURCE 200809L
#include "tg_tunnel.h"
#include "tg_listener.h"
#include "tg_session.h"
#include "tg_streams.h"
#include "tg_wire.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

enum { MUX_CONNECT=1,MUX_DATA=2,MUX_CLOSE=3,MUX_CONNECT_OK=4,MUX_CONNECT_FAIL=5,
       MUX_WINDOW=9,MUX_INFO=10 };
enum { INFO_RETRY_AFTER=1,INFO_GOODBYE=4 };

typedef struct { const tg_tunnel_config *config; tg_stream_table *streams; tg_ws_pump *pump; uint32_t retry_after; } relay_ctx;

static uint64_t monotonic_ms(void) {
    struct timespec ts;if(clock_gettime(CLOCK_MONOTONIC,&ts)!=0)return 0;
    return (uint64_t)ts.tv_sec*1000u+(uint64_t)ts.tv_nsec/1000000u;
}

static int queue_mux(tg_ws_pump *pump,uint16_t id,uint8_t type,const uint8_t *payload,size_t len) {
    if(len>65535) { return -1; }
    uint8_t *frame=malloc(len+3);if(!frame)return -1;
    size_t n=tg_mux_encode(frame,len+3,id,type,payload,len);
    int rc=n?tg_ws_pump_queue_binary(pump,frame,n):-1;free(frame);return rc;
}

static void close_local_stream(tg_stream_table *table,tg_stream *s,int notify_relay,tg_ws_pump *pump) {
    if(!s)return;
    if(notify_relay)(void)queue_mux(pump,s->id,MUX_CLOSE,NULL,0);
    tg_stream_remove(table,s);
}

static int relay_message(void *opaque,const uint8_t *bytes,size_t len) {
    relay_ctx *ctx=opaque;tg_frame f;
    if(tg_mux_decode(bytes,len,&f)!=0)return -1;
    if(f.stream_id==0) {
        if(f.type!=MUX_INFO)return -1;
        uint8_t kind;uint32_t arg;const uint8_t *text;size_t text_len;
        if(tg_info_decode(f.payload,f.payload_len,&kind,&arg,&text,&text_len)!=0)return -1;
        (void)text;(void)text_len;
        if(kind==INFO_RETRY_AFTER)ctx->retry_after=arg>TG_MAX_RETRY_AFTER_SEC?TG_MAX_RETRY_AFTER_SEC:arg;
        if(kind==INFO_GOODBYE)return -1;
        return 0;
    }
    tg_stream *s=tg_stream_find(ctx->streams,f.stream_id);if(!s)return 0;
    switch(f.type) {
    case MUX_CONNECT_OK: {
        if(!s->connect_pending)return -1;
        uint32_t credit=UINT32_MAX;
        if(ctx->config->protocol_v2 && tg_window_decode(f.payload,f.payload_len,&credit)!=0)return -1;
        if(tg_stream_connect_ok(ctx->streams,s,credit)!=0)return -1;
        return 0;
    }
    case MUX_CONNECT_FAIL:
        tg_stream_connect_fail(ctx->streams,s);tg_stream_remove(ctx->streams,s);return 0;
    case MUX_DATA:
        if(!s->connected || tg_stream_queue_remote_data(s,f.payload,f.payload_len)!=0) {
            close_local_stream(ctx->streams,s,1,ctx->pump);return 0;
        }
        s->last_activity_ms=monotonic_ms();
        return 0;
    case MUX_CLOSE:
        if(tg_stream_remote_close(s)!=0)return -1;
        if(tg_stream_ready_to_close(s)&&s->local_pending_len==0)tg_stream_remove(ctx->streams,s);
        return 0;
    case MUX_WINDOW: {
        uint32_t credit;if(!ctx->config->protocol_v2||tg_window_decode(f.payload,f.payload_len,&credit)!=0)return -1;
        tg_stream_grant_credit(s,credit);return 0;
    }
    default:return -1;
    }
}

static int set_nonblocking(int fd) {
    int flags=fcntl(fd,F_GETFL,0);return flags<0?-1:fcntl(fd,F_SETFL,flags|O_NONBLOCK);
}

static int send_connect(tg_stream *s,tg_stream_table *table,tg_ws_pump *pump) {
    int rc=tg_stream_connect_begin(table,s);if(rc!=0)return rc;
    uint8_t payload[19];size_t len=0;
    if(tg_connect_encode(payload,sizeof(payload),AF_INET,s->target_ipv4,s->target_port,&len)!=0 ||
       queue_mux(pump,s->id,MUX_CONNECT,payload,len)!=0) {
        tg_stream_connect_fail(table,s);return -1;
    }
    return 0;
}

static void accept_clients(const tg_tunnel_config *cfg,tg_stream_table *table,tg_ws_pump *pump) {
    for(;;) {
        int fd=accept(cfg->listener_fd,NULL,NULL);
        if(fd<0){if(errno==EINTR)continue;if(errno==EAGAIN||errno==EWOULDBLOCK)return;return;}
        if(tg_stream_table_count(table)>=table->capacity || set_nonblocking(fd)!=0) { close(fd);continue; }
        int one=1;(void)setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));
        (void)setsockopt(fd,SOL_SOCKET,SO_KEEPALIVE,&one,sizeof(one));
#ifdef TCP_KEEPIDLE
        int keepidle=60;(void)setsockopt(fd,IPPROTO_TCP,TCP_KEEPIDLE,&keepidle,sizeof(keepidle));
#endif
#ifdef SO_NOSIGPIPE
        (void)setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
#endif
        uint8_t ip[4];uint16_t port;
        int dst_rc=cfg->resolve_dst?cfg->resolve_dst(fd,ip,&port,cfg->resolve_dst_ctx)
                                  :tg_listener_get_original_dst(fd,&port,ip);
        uint16_t ports[]={cfg->listen_port};
        if(dst_rc!=0 || tg_listener_is_self_dial(ip,port,ports,1)) { close(fd);continue; }
        tg_stream *s=tg_stream_open(table);if(!s){close(fd);continue;}
        s->fd=fd;memcpy(s->target_ipv4,ip,4);s->target_port=port;s->connect_deadline_ms=monotonic_ms()+10000u;s->last_activity_ms=monotonic_ms();
        int rc=send_connect(s,table,pump);
        if(rc<0&&rc!=TG_STREAM_CONNECT_LIMITED){tg_stream_remove(table,s);continue;}
    }
}

static void start_waiting_connects(tg_stream_table *table,tg_ws_pump *pump,uint64_t now) {
    for(size_t i=0;i<table->capacity;i++) {
        tg_stream *s=table->items[i];if(!s||s->connected||s->connect_pending)continue;
        if(now>=s->connect_deadline_ms){close_local_stream(table,s,1,pump);continue;}
        int rc=send_connect(s,table,pump);if(rc<0&&rc!=TG_STREAM_CONNECT_LIMITED)close_local_stream(table,s,0,pump);
        if(table->connecting>=TG_STREAM_CONNECT_LIMIT)return;
    }
}

static void send_window_if_due(const tg_tunnel_config *cfg,tg_ws_pump *pump,tg_stream *s,uint32_t written) {
    if(!cfg->protocol_v2) { return; }
    uint32_t credit=0;
    if(tg_stream_local_write_complete(s,written,&credit)!=0||!credit)return;
    uint8_t payload[4];(void)tg_window_encode(payload,credit);
    (void)queue_mux(pump,s->id,MUX_WINDOW,payload,sizeof(payload));
}

static void service_local_fd(const tg_tunnel_config *cfg,tg_stream_table *table,
                             tg_ws_pump *pump,tg_stream *s,short revents) {
    if(!s||s->fd<0)return;
    if(revents&(POLLERR|POLLNVAL)){close_local_stream(table,s,1,pump);return;}
    if((revents&POLLOUT) && (s->local_pending_len || s->to_local.bytes)) {
        if(!s->local_pending_len) {
            size_t n=0;if(tg_stream_pop_local(s,s->local_pending,sizeof(s->local_pending),&n)!=0){close_local_stream(table,s,1,pump);return;}
            s->local_pending_len=n;s->local_pending_offset=0;
        }
        if(s->local_pending_len) {
            int send_flags=0;
#ifdef MSG_NOSIGNAL
            send_flags=MSG_NOSIGNAL;
#endif
            ssize_t n=send(s->fd,s->local_pending+s->local_pending_offset,
                           s->local_pending_len-s->local_pending_offset,send_flags);
            if(n>0){s->last_activity_ms=monotonic_ms();s->local_pending_offset+=(size_t)n;
                if(s->local_pending_offset==s->local_pending_len){uint32_t sent=(uint32_t)s->local_pending_len;
                    s->local_pending_len=0;s->local_pending_offset=0;send_window_if_due(cfg,pump,s,sent);}}
            else if(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR){close_local_stream(table,s,1,pump);return;}
        }
    }
    if((revents&POLLIN)&&s->connected&&!s->remote_closed&&!s->local_eof) {
        uint8_t data[16384];size_t want=sizeof(data);
        if(cfg->protocol_v2 && s->send_credit<want)want=(size_t)s->send_credit;
        if(want) {
            ssize_t n=recv(s->fd,data,want,0);
            if(n>0) {
                s->last_activity_ms=monotonic_ms();
                if(tg_stream_send_data(s,data,(size_t)n)!=0 || queue_mux(pump,s->id,MUX_DATA,data,(size_t)n)!=0)
                    close_local_stream(table,s,1,pump);
            } else if(n==0){tg_stream_local_eof(s);close_local_stream(table,s,1,pump);return;}
            else if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR){close_local_stream(table,s,1,pump);return;}
        }
    }
    if(revents&POLLHUP) {
        uint8_t data[1];ssize_t n=recv(s->fd,data,sizeof(data),MSG_PEEK);
        if(n==0)close_local_stream(table,s,1,pump);
    }
    if(s->remote_closed&&tg_stream_ready_to_close(s)&&s->local_pending_len==0)tg_stream_remove(table,s);
}

int tg_tunnel_run(const tg_tunnel_config *cfg) {
    tg_ws_pump pump;tg_stream_table streams;relay_ctx relay;
    if(!cfg||!cfg->relay_ssl||cfg->listener_fd<0||!cfg->stop)return -1;
    if(tg_ws_pump_init(&pump,cfg->relay_ssl)!=0)return -1;
    /* Keep the donor's 16 MiB payload cap and independently bound owned
     * stream/table/queue storage, including each stream's local_pending. */
    tg_stream_table_init(&streams,TG_STREAM_MAX,TG_STREAM_MEMORY_LIMIT,cfg->window);
    if(!streams.items){tg_ws_pump_destroy(&pump);return -1;}
    relay=(relay_ctx){.config=cfg,.streams=&streams,.pump=&pump};
    uint64_t last_rx=monotonic_ms(),last_ping=last_rx;
    int result=0;
    while(!*cfg->stop&&!pump.failed&&!pump.closed) {
        uint64_t loop_now=monotonic_ms();
        for(size_t i=0;i<streams.capacity;i++) {
            tg_stream *s=streams.items[i];if(!s||!s->connected)continue;
            if(loop_now>=s->last_activity_ms&&loop_now-s->last_activity_ms>=TG_STREAM_IDLE_TIMEOUT_MS)
                close_local_stream(&streams,s,1,&pump);
        }
        struct pollfd fds[TG_STREAM_MAX+2];tg_stream *map[TG_STREAM_MAX];nfds_t count=2;
        fds[0]=(struct pollfd){.fd=cfg->listener_fd,.events=POLLIN};
        fds[1]=(struct pollfd){.fd=tg_ws_pump_fd(&pump),.events=tg_ws_pump_events(&pump)};
        for(size_t i=0;i<streams.capacity;i++) {
            tg_stream *s=streams.items[i];if(!s||s->fd<0)continue;
            short events=0;
            if(s->connected&&!s->remote_closed&&!s->local_eof&&(!cfg->protocol_v2||s->send_credit))events|=POLLIN;
            if(s->local_pending_len||s->to_local.bytes)events|=POLLOUT;
            if(events){fds[count]=(struct pollfd){.fd=s->fd,.events=events};map[count-2]=s;count++;}
        }
        int timeout=1000;uint64_t now=monotonic_ms();
        if(tg_session_read_expired(last_rx,now)){result=-1;break;}
        if(tg_session_ping_due(last_ping,now)){
            static const uint8_t ping_payload[8]={0x44,0x32,0x4b,0x54,0,0,0,1};
            if(tg_ws_pump_queue_ping(&pump,ping_payload,sizeof(ping_payload))!=0){result=-1;break;}
            last_ping=now;
        }
        if(now-last_ping<TG_WS_PING_INTERVAL_MS && TG_WS_PING_INTERVAL_MS-(now-last_ping)<(uint64_t)timeout)
            timeout=(int)(TG_WS_PING_INTERVAL_MS-(now-last_ping));
        if(now-last_rx<TG_WS_READ_TIMEOUT_MS && TG_WS_READ_TIMEOUT_MS-(now-last_rx)<(uint64_t)timeout)
            timeout=(int)(TG_WS_READ_TIMEOUT_MS-(now-last_rx));
        for(size_t i=0;i<streams.capacity;i++) {
            tg_stream *s=streams.items[i];
            if(s&&!s->connected) {
                if(now>=s->connect_deadline_ms){close_local_stream(&streams,s,1,&pump);continue;}
                uint64_t left=s->connect_deadline_ms-now;if(left<(uint64_t)timeout)timeout=(int)left;
            } else if(s&&s->connected&&now>=s->last_activity_ms) {
                uint64_t idle=now-s->last_activity_ms;
                if(idle<TG_STREAM_IDLE_TIMEOUT_MS&&TG_STREAM_IDLE_TIMEOUT_MS-idle<(uint64_t)timeout)
                    timeout=(int)(TG_STREAM_IDLE_TIMEOUT_MS-idle);
            }
        }
        int ready=poll(fds,count,timeout);
        if(ready<0){if(errno==EINTR)continue;result=-1;break;}
        if(fds[0].revents&POLLIN)accept_clients(cfg,&streams,&pump);
        for(nfds_t i=2;i<count;i++)service_local_fd(cfg,&streams,&pump,map[i-2],fds[i].revents);
        if(fds[1].revents||SSL_pending(cfg->relay_ssl)>0) {
            if((fds[1].revents&POLLIN)||SSL_pending(cfg->relay_ssl)>0)last_rx=monotonic_ms();
            if(tg_ws_pump_process(&pump,fds[1].revents,relay_message,&relay)!=0){result=-1;break;}
        }
        now=monotonic_ms();start_waiting_connects(&streams,&pump,now);
        if(relay.retry_after){result=(int)relay.retry_after;break;}
    }
    if(pump.failed)result=-1;
    tg_stream_table_destroy(&streams);tg_ws_pump_destroy(&pump);
    return result;
}
