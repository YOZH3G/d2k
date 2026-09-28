#ifndef D2K_TG_NET_H
#define D2K_TG_NET_H

#include <stdint.h>

/* Returns 1 when an IPv4 address was extracted, 0 for ordinary/noncanonical
 * hosts. This deliberately recognizes only the donor's a.b.c.d.nip.io form. */
int tg_nip_host_to_ipv4(const char *hostname, char out[16]);
int tg_tcp_connect_ipv4(const char *hostname, uint16_t port, unsigned timeout_ms);

#endif
