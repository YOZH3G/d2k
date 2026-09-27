#define _POSIX_C_SOURCE 200809L
#include "server.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
    int fd;
    const d2k_panel_config *cfg;
} server_call;

static void *serve_thread(void *arg) {
    server_call *call = arg;
    (void)d2k_panel_handle_fd(call->fd, call->cfg);
    close(call->fd);
    return NULL;
}

static void write_all(int fd, const char *s) {
    size_t n = strlen(s), off = 0;
    while (off < n) {
        ssize_t wr = write(fd, s + off, n - off);
        assert(wr > 0);
        off += (size_t)wr;
    }
}

static void send_request(int fd, const char *s) {
    size_t n = strlen(s), off = 0;
    while (off < n) {
        ssize_t wr = write(fd, s + off, n - off);
        if (wr <= 0) { return; } /* handler may correctly reject and close early */
        off += (size_t)wr;
    }
}

static size_t request(const d2k_panel_config *cfg, const char *req,
                      char *response, size_t cap) {
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    server_call call = { .fd = sv[1], .cfg = cfg };
    pthread_t thread;
    assert(pthread_create(&thread, NULL, serve_thread, &call) == 0);
    send_request(sv[0], req);
    (void)shutdown(sv[0], SHUT_WR);
    size_t used = 0;
    char drain[4096];
    for (;;) {
        char *dst = used + 1 < cap ? response + used : drain;
        size_t room = used + 1 < cap ? cap - used - 1 : sizeof drain;
        ssize_t n = read(sv[0], dst, room);
        if (n <= 0) { break; }
        if (used + 1 < cap) { used += (size_t)n; }
    }
    response[used] = '\0';
    assert(pthread_join(thread, NULL) == 0);
    close(sv[0]);
    return used;
}

static void write_temp_file(char path[], const char *contents) {
    int fd = mkstemp(path);
    assert(fd >= 0);
    write_all(fd, contents);
    close(fd);
}

static void test_api_exposes_live_knowledge(void) {
    char live[] = "/tmp/d2k-panel-live.XXXXXX";
    write_temp_file(live, "{\"linked\":true,\"link_note\":\"\",\"boxes\":[],\"searches\":[],\"targets\":0,\"confirms\":0,\"probes_used\":0,\"client_unfit\":0}");

    static const char *unknown[] = { "FUTURE_OPTION" };
    d2k_panel_config cfg = {
        .live_path = live,
        .asset_dir = "panel/assets",
        .version = "test-version",
        .commit = "0123456789abcdef",
        .built = "2026-09-27T00:00:00Z",
        .mode = "observe",
        .panel_listen = "127.0.0.1:8090",
        .config_path = "/tmp/d2k/config",
        .state_dir = "/tmp/d2k/state",
        .state_dir_note = "есть",
        .unknown_keys = unknown,
        .unknown_key_count = 1,
        .queue_num = 2000,
        .started_epoch = 1,
        .config_exists = 1,
    };
    char response[32768];
    (void)request(&cfg, "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
                  response, sizeof response);
    assert(strstr(response, "HTTP/1.1 200 OK") != NULL);
    assert(strstr(response, "Content-Type: application/json; charset=utf-8") != NULL);
    assert(strstr(response, "\"snapshot\":{\"taken\":") != NULL);
    assert(strstr(response, "\"version\":\"test-version\"") != NULL);
    assert(strstr(response, "\"unknown_keys\":[\"FUTURE_OPTION\"]") != NULL);
    assert(strstr(response, "\"linked\":true") != NULL);
    assert(strstr(response, "Content-Security-Policy:") != NULL);
    unlink(live);
}

static void test_invalid_live_json_is_not_reported_as_empty_knowledge(void) {
    char live[] = "/tmp/d2k-panel-invalid.XXXXXX";
    write_temp_file(live, "{broken json}");
    d2k_panel_config cfg = {
        .live_path = live,
        .asset_dir = "panel/assets",
        .version = "test-version",
        .commit = "0123456789abcdef",
        .built = "2026-09-27T00:00:00Z",
        .mode = "observe",
        .panel_listen = "127.0.0.1:8090",
        .config_path = "/tmp/d2k/config",
        .state_dir = "/tmp/d2k/state",
        .state_dir_note = "есть",
        .queue_num = 2000,
        .started_epoch = 1,
        .config_exists = 1,
    };
    char response[4096];
    (void)request(&cfg, "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
                  response, sizeof response);
    assert(strstr(response, "HTTP/1.1 200 OK") != NULL);
    assert(strstr(response, "\"linked\":false") != NULL);
    assert(strstr(response, "движок не отдаёт состояние") != NULL);
    assert(strstr(response, "broken json") == NULL);
    unlink(live);
}

static void test_unsupported_method_is_rejected(void) {
    d2k_panel_config cfg = { .live_path = "/absent", .asset_dir = "panel/assets" };
    char response[4096];
    (void)request(&cfg, "POST /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
                  response, sizeof response);
    assert(strstr(response, "HTTP/1.1 405 Method Not Allowed") != NULL);
}

static void test_unknown_and_traversal_paths_are_not_served(void) {
    d2k_panel_config cfg = { .live_path = "/absent", .asset_dir = "panel/assets" };
    char response[4096];
    (void)request(&cfg, "GET /../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n",
                  response, sizeof response);
    assert(strstr(response, "HTTP/1.1 404 Not Found") != NULL);
    assert(strstr(response, "root:") == NULL);
}

static void test_oversized_request_header_gets_431(void) {
    size_t n = 40u * 1024u;
    char *req = malloc(n + 128);
    assert(req != NULL);
    size_t used = (size_t)snprintf(req, n + 128,
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Large: ");
    memset(req + used, 'a', n);
    used += n;
    memcpy(req + used, "\r\n\r\n", 5);
    d2k_panel_config cfg = { .live_path = "/absent", .asset_dir = "panel/assets" };
    char response[4096];
    (void)request(&cfg, req, response, sizeof response);
    assert(strstr(response, "HTTP/1.1 431 Request Header Fields Too Large") != NULL);
    free(req);
}

static void test_asset_symlink_cannot_escape_asset_directory(void) {
    char dir[PATH_MAX];
    int dn = snprintf(dir, sizeof dir, "/tmp/d2k-panel-assets.%ld", (long)getpid());
    assert(dn > 0 && (size_t)dn < sizeof dir);
    assert(mkdir(dir, 0700) == 0);
    char linkpath[PATH_MAX];
    int n = snprintf(linkpath, sizeof linkpath, "%s/panel.css", dir);
    assert(n > 0 && (size_t)n < sizeof linkpath);
    assert(symlink("/etc/passwd", linkpath) == 0);
    d2k_panel_config cfg = { .live_path = "/absent", .asset_dir = dir };
    char response[4096];
    (void)request(&cfg, "GET /assets/panel.css HTTP/1.1\r\nHost: localhost\r\n\r\n",
                  response, sizeof response);
    assert(strstr(response, "HTTP/1.1 404 Not Found") != NULL);
    assert(strstr(response, "root:") == NULL);
    unlink(linkpath);
    rmdir(dir);
}

static void test_root_serves_static_offline_panel_shell(void) {
    d2k_panel_config cfg = {
        .live_path = "/absent",
        .asset_dir = "../internal/web/assets",
    };
    char response[8192];
    (void)request(&cfg, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                  response, sizeof response);
    assert(strstr(response, "HTTP/1.1 200 OK") != NULL);
    assert(strstr(response, "Content-Type: text/html; charset=utf-8") != NULL);
    assert(strstr(response, "id=\"app\"") != NULL);
    assert(strstr(response, "src=\"/assets/panel.js\"") != NULL);
}

static void test_panel_javascript_is_served_same_origin(void) {
    d2k_panel_config cfg = {
        .live_path = "/absent",
        .asset_dir = "../internal/web/assets",
    };
    char response[8192];
    (void)request(&cfg, "GET /assets/panel.js HTTP/1.1\r\nHost: localhost\r\n\r\n",
                  response, sizeof response);
    assert(strstr(response, "HTTP/1.1 200 OK") != NULL);
    assert(strstr(response, "Content-Type: application/javascript; charset=utf-8") != NULL);
}

static void test_disconnected_client_cannot_sigpipe_server(void) {
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        (void)signal(SIGPIPE, SIG_DFL);
        d2k_panel_ignore_sigpipe();
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { _exit(10); }
        const char req[] = "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n";
        if (write(sv[0], req, sizeof req - 1) != (ssize_t)(sizeof req - 1)) { _exit(11); }
        shutdown(sv[0], SHUT_RDWR);
        close(sv[0]);
        d2k_panel_config cfg = { .live_path = "/absent", .asset_dir = "panel/assets" };
        (void)d2k_panel_handle_fd(sv[1], &cfg);
        close(sv[1]);
        _exit(0);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    test_api_exposes_live_knowledge();
    test_invalid_live_json_is_not_reported_as_empty_knowledge();
    test_unsupported_method_is_rejected();
    test_unknown_and_traversal_paths_are_not_served();
    test_oversized_request_header_gets_431();
    test_asset_symlink_cannot_escape_asset_directory();
    test_root_serves_static_offline_panel_shell();
    test_panel_javascript_is_served_same_origin();
    test_disconnected_client_cannot_sigpipe_server();
    puts("C panel HTTP contract: all checks passed");
    return 0;
}
