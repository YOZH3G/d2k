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

#endif
