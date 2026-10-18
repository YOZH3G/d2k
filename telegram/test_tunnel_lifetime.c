#define _DARWIN_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include "src/tunnel.c"

/* Exercise the event handler with real socketpairs and real queue ownership.
 * Including tunnel.c keeps its private handler out of the production API. */
static void test_close(short events, int queue_full, int pending) {
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    tg_stream_table table;
    tg_stream_table_init(&table, 2, 65536, 0);
    tg_stream *s = tg_stream_open(&table), *other = tg_stream_open(&table);
    assert(s && other);
    uint16_t id = s->id, other_id = other->id;
    s->fd = sockets[0];
    assert(set_nonblocking(s->fd) == 0);
    assert(tg_stream_connect_begin(&table, s) == 0);
    assert(tg_stream_connect_ok(&table, s, UINT32_MAX) == 0);
    tg_ws_pump pump = {0};
    if (queue_full) {
        uint8_t payload[16384] = {0};
        while (tg_ws_pump_queue_binary(&pump, payload, sizeof payload) == 0) {}
        /* Fill the remaining space too, so even a tiny DATA frame fails. */
        while (tg_ws_pump_queue_binary(&pump, payload, 1) == 0) {}
        assert(write(sockets[1], "x", 1) == 1);
    } else {
        assert(shutdown(sockets[1], SHUT_WR) == 0);
    }
    if (pending) {
        s->local_pending[0] = 'p';
        s->local_pending_len = 1;
        assert(tg_stream_queue_remote_data(s, (const uint8_t *)"q", 1) == 0);
    }
    tg_tunnel_config cfg = {0};
    service_local_fd(&cfg, &table, &pump, s, events);
    assert(tg_stream_find(&table, id) == NULL);
    assert(tg_stream_table_count(&table) == 1);
    assert(tg_stream_find(&table, other_id) == other);
    assert(table.queued_bytes == 0);
    tg_ws_pump_destroy(&pump);
    tg_stream_table_destroy(&table);
    close(sockets[1]);
}

static void test_remote_close_drains_pending(void) {
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    tg_stream_table table;
    tg_stream_table_init(&table, 1, 65536, 0);
    tg_stream *s = tg_stream_open(&table);
    assert(s); s->fd = sockets[0];
    uint16_t id = s->id;
    assert(tg_stream_queue_remote_data(s, (const uint8_t *)"pending", 7) == 0);
    assert(tg_stream_remote_close(s) == 0);
    tg_ws_pump pump = {0};
    tg_tunnel_config cfg = {0};
    service_local_fd(&cfg, &table, &pump, s, 0);
    assert(tg_stream_find(&table, id) == s);
    service_local_fd(&cfg, &table, &pump, s, POLLOUT);
    assert(tg_stream_find(&table, id) == NULL);
    char data[7];
    assert(read(sockets[1], data, sizeof data) == sizeof data);
    assert(memcmp(data, "pending", sizeof data) == 0);
    tg_stream_table_destroy(&table); close(sockets[1]);
}

int main(void) {
    test_close(POLLHUP, 0, 1);
    test_close(POLLIN | POLLHUP, 1, 1);
    test_close(POLLIN, 1, 0);
    test_close(POLLIN | POLLHUP, 0, 0);
    test_remote_close_drains_pending();
    puts("tunnel lifetime tests: ok");
    return 0;
}
