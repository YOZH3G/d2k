/* Safe, opt-in HTTP-to-HTTPS upgrade helpers for the transparent port-80 shim. */
#ifndef D2K_HTTPUP_H
#define D2K_HTTPUP_H

#include <stddef.h>

/* True only for a syntactically valid origin-form GET/HEAD with no body. */
int d2k_httpup_request_safe(const char *request, size_t request_len);

/* Only after inspecting a real cross-host HTTP 30x whose destination host has
 * an explicit generic filter-portal marker, suggest HTTPS for the requested
 * origin. Returns 1 with a 307, otherwise the exact upstream response is
 * relayed unchanged. */
int d2k_httpup_portal_response(const char *request, size_t request_len,
                               const char *upstream, size_t upstream_len,
                               char *response, size_t response_cap);

/* Pieces of the same decision for the datapath (task 51): the request and the
 * response arrive in different packets, so the request is remembered as its
 * host (port and trailing dot stripped) and origin-form target. */
int d2k_httpup_request_target(const char *request, size_t request_len,
                              char *host, size_t host_cap,
                              char *target, size_t target_cap);
/* 1 and the portal host when the response head is the same cross-host portal
 * 30x that d2k_httpup_portal_response recognises. */
int d2k_httpup_portal_location(const char *host, const char *response, size_t response_len,
                               char *portal, size_t portal_cap);
/* The 307 to https://host+target; length, 0 if it does not fit. */
size_t d2k_httpup_redirect_https(const char *host, const char *target,
                                 char *response, size_t response_cap);

#endif
