#ifndef D2K_VOICE_DISCOVERY_H
#define D2K_VOICE_DISCOVERY_H
#include "d2k_voice.h"
/* Field 04.10: direct UDP stops at 25 total packets. 25 request/reply
 * exchanges verify twice that observed window; this is a verification
 * extent, not a limit on strategy search or a claim of application health. */
#define D2K_DISCOVERY_EXCHANGES 25
typedef struct { unsigned sent, received; int error, marked; } d2k_discovery_result;
typedef d2k_discovery_result (*d2k_discovery_probe_fn)(uint32_t, uint16_t,
    const uint8_t *, size_t, uint32_t, uint32_t);
extern d2k_discovery_probe_fn d2k_discovery_probe_hook;
int d2k_discovery_response(const uint8_t *, size_t, const uint8_t ssrc[4]);
/* Accept only the complete single-prefix plan this measurement emits. */
int d2k_voice_discovery_prefix(const char *, uint8_t prefix[20]);
/* 0: no Discord oracle; caller retains the existing STUN/live-flow path.
 * 1: result filled, including local errors and inconclusive comparisons. */
int d2k_voice_discovery_search(const d2k_voice_opt *, d2k_voice_res *);
#endif
