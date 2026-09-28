#define _POSIX_C_SOURCE 200809L
#include "tg_config.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void test_config_values_and_url(void) {
    char path[]="/tmp/d2k-tg-config-XXXXXX";int fd=mkstemp(path);assert(fd>=0);
    FILE *f=fdopen(fd,"w");assert(f);
    fputs("MODE=apply\nTG_ENABLED=1\nTG_RELAY_URL='wss://213.176.74.63.nip.io/ws'\nTG_RELAY_SECRET='never-log-this'\nTG_IDENTITY=/opt/d2k/state/tg.identity\nTG_CA_BUNDLE=/opt/d2k/files/tg-roots.pem\nTG_STATUS=/opt/d2k/state/telegram.status\nTG_PORT=1443\n",f);assert(fclose(f)==0);
    tg_config cfg;assert(tg_config_read(path,&cfg)==0);unlink(path);
    assert(cfg.enabled==1&&cfg.listen_port==1443&&strcmp(cfg.relay_secret,"never-log-this")==0);
    tg_relay_url url;assert(tg_relay_url_parse(cfg.relay_url,&url)==0);
    assert(strcmp(url.host,"213.176.74.63.nip.io")==0&&url.port==443&&strcmp(url.path,"/ws")==0);
    tg_config_clean(&cfg);
}

static void test_url_rejects_unsafe_or_unsupported_inputs(void) {
    tg_relay_url url;
    assert(tg_relay_url_parse("ws://relay.example/ws",&url)!=0);
    assert(tg_relay_url_parse("wss://user@relay.example/ws",&url)!=0);
    assert(tg_relay_url_parse("wss://relay.example/ws?secret=x",&url)!=0);
    assert(tg_relay_url_parse("wss://relay.example/other",&url)!=0);
    assert(tg_relay_url_parse("wss://relay.example:0/ws",&url)!=0);
    assert(tg_relay_url_parse("wss://relay.example:65536/ws",&url)!=0);
    assert(tg_relay_url_parse("wss://-relay.example/ws",&url)!=0);
    assert(tg_relay_url_parse("wss://relay-.example/ws",&url)!=0);
    assert(tg_relay_url_parse("wss://relay..example/ws",&url)!=0);
    assert(tg_relay_url_parse("wss://relay.example:8443/ws",&url)==0&&url.port==8443);
}

static void test_duplicate_and_incomplete_keys_rejected(void) {
    char path[]="/tmp/d2k-tg-config-XXXXXX";int fd=mkstemp(path);assert(fd>=0);
    FILE *f=fdopen(fd,"w");assert(f);fputs("TG_ENABLED=1\nTG_ENABLED=0\n",f);assert(fclose(f)==0);
    tg_config cfg;assert(tg_config_read(path,&cfg)!=0);unlink(path);
    assert(tg_config_read("/path/that/does/not/exist",&cfg)!=0);
}

int main(void) {
    test_config_values_and_url();test_url_rejects_unsafe_or_unsupported_inputs();
    test_duplicate_and_incomplete_keys_rejected();puts("config tests: ok");return 0;
}
