#ifndef D2K_TG_TUNNEL_H
#define D2K_TG_TUNNEL_H

#include "tg_ws.h"
#include <signal.h>
#include <stdint.h>

typedef int (*tg_original_dst_fn)(int fd,uint8_t ipv4[4],uint16_t *port,void *ctx);
typedef struct {
    SSL *relay_ssl; int listener_fd; uint16_t listen_port;
    int protocol_v2; uint32_t window; volatile sig_atomic_t *stop;
    tg_original_dst_fn resolve_dst; void *resolve_dst_ctx;
} tg_tunnel_config;

/* Runs one relay session and services redirected local TCP connections until
 * stop is set or the relay session is lost. The caller owns SSL/listener_fd. */
int tg_tunnel_run(const tg_tunnel_config *config);

#endif
