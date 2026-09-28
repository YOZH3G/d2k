#ifndef D2K_TG_REGISTER_H
#define D2K_TG_REGISTER_H

#include "tg_identity.h"
#include <stdint.h>

#define TG_REGISTER_ID_CONFLICT (-2)

/* connect_ip may be an IPv4 literal to bypass broken DNS while hostname is
 * retained for TLS SNI, certificate checks and the HTTP Host header. */
int tg_register_identity(const char *hostname, uint16_t port,
                         const char *connect_ip, const char *ca_bundle,
                         const char *secret, const tg_identity *identity);

#endif
