#ifndef D2K_TG_CONFIG_H
#define D2K_TG_CONFIG_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    int enabled;
    char relay_url[512];
    char relay_secret[512];
    char identity_path[512];
    char ca_bundle[512];
    char status_path[512];
    uint16_t listen_port;
} tg_config;

typedef struct {
    char host[256];
    char path[128];
    uint16_t port;
} tg_relay_url;

/* Strictly reads only Telegram-owned keys; unknown D2K config keys are ignored. */
int tg_config_read(const char *path, tg_config *out);
int tg_relay_url_parse(const char *url, tg_relay_url *out);
void tg_config_clean(tg_config *config);

#endif
