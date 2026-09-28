#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include "server.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#define REQUEST_MAX (32u * 1024u)
#define BODY_MAX (1024u * 1024u)

int d2k_panel_ignore_sigpipe(void) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = SIG_IGN;
    if (sigemptyset(&action.sa_mask) != 0) { return -1; }
    return sigaction(SIGPIPE, &action, NULL);
}

typedef struct { const char *p, *end; unsigned depth; } json_reader;

static void json_ws(json_reader *r) {
    while (r->p < r->end && (*r->p == ' ' || *r->p == '\t' ||
                              *r->p == '\r' || *r->p == '\n')) { r->p++; }
}

static int json_string(json_reader *r) {
    if (r->p >= r->end || *r->p++ != '"') { return -1; }
    while (r->p < r->end) {
        unsigned char c = (unsigned char)*r->p++;
        if (c == '"') { return 0; }
        if (c < 0x20) { return -1; }
        if (c != '\\') { continue; }
        if (r->p >= r->end) { return -1; }
        c = (unsigned char)*r->p++;
        if (c == '"' || c == '\\' || c == '/' || c == 'b' || c == 'f' ||
            c == 'n' || c == 'r' || c == 't') { continue; }
        if (c != 'u' || r->end - r->p < 4) { return -1; }
        for (int i = 0; i < 4; i++) {
            unsigned char h = (unsigned char)*r->p++;
            if (!((h >= '0' && h <= '9') || (h >= 'a' && h <= 'f') ||
                  (h >= 'A' && h <= 'F'))) { return -1; }
        }
    }
    return -1;
}

static int json_value(json_reader *r);

static int json_compound(json_reader *r, char open, char close, int object) {
    if (++r->depth > 64 || r->p >= r->end || *r->p++ != open) {
        r->depth--;
        return -1;
    }
    json_ws(r);
    if (r->p < r->end && *r->p == close) { r->p++; r->depth--; return 0; }
    for (;;) {
        if (object) {
            if (json_string(r) != 0) { r->depth--; return -1; }
            json_ws(r);
            if (r->p >= r->end || *r->p++ != ':') { r->depth--; return -1; }
            json_ws(r);
        }
        if (json_value(r) != 0) { r->depth--; return -1; }
        json_ws(r);
        if (r->p >= r->end) { r->depth--; return -1; }
        char c = *r->p++;
        if (c == close) { r->depth--; return 0; }
        if (c != ',') { r->depth--; return -1; }
        json_ws(r);
    }
}

static int json_number(json_reader *r) {
    const char *p = r->p;
    if (p < r->end && *p == '-') { p++; }
    if (p >= r->end) { return -1; }
    if (*p == '0') { p++; }
    else {
        if (*p < '1' || *p > '9') { return -1; }
        do { p++; } while (p < r->end && *p >= '0' && *p <= '9');
    }
    if (p < r->end && *p == '.') {
        p++;
        if (p >= r->end || *p < '0' || *p > '9') { return -1; }
        do { p++; } while (p < r->end && *p >= '0' && *p <= '9');
    }
    if (p < r->end && (*p == 'e' || *p == 'E')) {
        p++;
        if (p < r->end && (*p == '+' || *p == '-')) { p++; }
        if (p >= r->end || *p < '0' || *p > '9') { return -1; }
        do { p++; } while (p < r->end && *p >= '0' && *p <= '9');
    }
    r->p = p;
    return 0;
}

static int json_value(json_reader *r) {
    json_ws(r);
    if (r->p >= r->end) { return -1; }
    switch (*r->p) {
    case '"': return json_string(r);
    case '{': return json_compound(r, '{', '}', 1);
    case '[': return json_compound(r, '[', ']', 0);
    case 't': if (r->end - r->p >= 4 && memcmp(r->p, "true", 4) == 0) { r->p += 4; return 0; } return -1;
    case 'f': if (r->end - r->p >= 5 && memcmp(r->p, "false", 5) == 0) { r->p += 5; return 0; } return -1;
    case 'n': if (r->end - r->p >= 4 && memcmp(r->p, "null", 4) == 0) { r->p += 4; return 0; } return -1;
    default: return json_number(r);
    }
}

static int json_valid_object(const char *p, const char *end) {
    json_reader r = { .p = p, .end = end, .depth = 0 };
    json_ws(&r);
    if (r.p >= r.end || *r.p != '{' || json_value(&r) != 0) { return 0; }
    json_ws(&r);
    return r.p == r.end;
}

static int json_top_value(const char *json, const char *wanted,
                          const char **value, size_t *value_len) {
    json_reader r = { .p = json, .end = json + strlen(json), .depth = 0 };
    json_ws(&r);
    if (r.p >= r.end || *r.p++ != '{') { return 0; }
    json_ws(&r);
    while (r.p < r.end && *r.p != '}') {
        const char *key_start = r.p;
        if (json_string(&r) != 0) { return 0; }
        size_t key_len = (size_t)(r.p - key_start);
        json_ws(&r);
        if (r.p >= r.end || *r.p++ != ':') { return 0; }
        json_ws(&r);
        const char *value_start = r.p;
        int match = strlen(wanted) + 2 == key_len && key_start[0] == '"' &&
                    key_start[key_len - 1] == '"' &&
                    memcmp(key_start + 1, wanted, strlen(wanted)) == 0;
        if (json_value(&r) != 0) { return 0; }
        if (match) {
            *value = value_start;
            *value_len = (size_t)(r.p - value_start);
            return 1;
        }
        json_ws(&r);
        if (r.p >= r.end || *r.p == '}') { break; }
        if (*r.p++ != ',') { return 0; }
        json_ws(&r);
    }
    return 0;
}

static int json_top_true(const char *json, const char *key) {
    const char *value;
    size_t len;
    return json_top_value(json, key, &value, &len) && len == 4 &&
           memcmp(value, "true", 4) == 0;
}

static int json_top_nonempty_string(const char *json, const char *key) {
    const char *value;
    size_t len;
    return json_top_value(json, key, &value, &len) && len > 2 &&
           value[0] == '"' && value[len - 1] == '"';
}

static int pid_path_running(const char *path, time_t *started_at) {
    if (started_at) { *started_at = 0; }
    if (!path || !path[0]) { return 1; }
    FILE *f = fopen(path, "r");
    if (!f) { return 0; }
    struct stat st;
    int have_stat = fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode);
    char line[32];
    int ok = fgets(line, sizeof line, f) != NULL;
    fclose(f);
    if (!ok || !have_stat) { return 0; }
    char *end = NULL;
    errno = 0;
    long value = strtol(line, &end, 10);
    if (errno || value <= 1 || value > 4194304L || !end) { return 0; }
    while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n') { end++; }
    if (*end) { return 0; }
    int running = kill((pid_t)value, 0) == 0 || errno == EPERM;
    if (running && started_at) { *started_at = st.st_mtime; }
    return running;
}

static int engine_pid_running(const d2k_panel_config *cfg, time_t *started_at) {
    return pid_path_running(cfg ? cfg->engine_pid_path : NULL, started_at);
}

static int controller_pid_running(const d2k_panel_config *cfg) {
    return pid_path_running(cfg ? cfg->controller_pid_path : NULL, NULL);
}

static int write_all(int fd, const void *buf, size_t len) {
    const char *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0 && errno == EINTR) { continue; }
        if (n <= 0) { return -1; }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int response(int fd, int code, const char *reason, const char *type,
                    const char *body, size_t len) {
    char hdr[1024];
    int n = snprintf(hdr, sizeof hdr,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; connect-src 'self'; script-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Referrer-Policy: no-referrer\r\n\r\n",
        code, reason, type, len);
    if (n < 0 || (size_t)n >= sizeof hdr) { return -1; }
    if (write_all(fd, hdr, (size_t)n) != 0) { return -1; }
    return len == 0 ? 0 : write_all(fd, body, len);
}

static int header_value(const char *req, const char *wanted,
                        const char **value, size_t *value_len) {
    const char *line = strstr(req, "\r\n");
    if (!line) { return 0; }
    line += 2;
    while (*line && !(line[0] == '\r' && line[1] == '\n')) {
        const char *end = strstr(line, "\r\n");
        if (!end) { return 0; }
        const char *colon = memchr(line, ':', (size_t)(end - line));
        if (colon && (size_t)(colon - line) == strlen(wanted) &&
            strncasecmp(line, wanted, strlen(wanted)) == 0) {
            const char *start = colon + 1;
            while (start < end && (*start == ' ' || *start == '\t')) { start++; }
            const char *finish = end;
            while (finish > start && (finish[-1] == ' ' || finish[-1] == '\t')) { finish--; }
            *value = start;
            *value_len = (size_t)(finish - start);
            return 1;
        }
        line = end + 2;
    }
    return 0;
}

static int same_origin(const char *req) {
    const char *host = NULL, *origin = NULL;
    size_t host_len = 0, origin_len = 0;
    if (!header_value(req, "Host", &host, &host_len) ||
        !header_value(req, "Origin", &origin, &origin_len) ||
        origin_len < 7 || memcmp(origin, "http://", 7) != 0) { return 0; }
    const char *authority = origin + 7;
    size_t authority_len = origin_len - 7;
    return host_len == authority_len &&
           memcmp(host, authority, host_len) == 0;
}

static int run_service_action(const d2k_panel_config *cfg, const char *action) {
    if (!cfg || !cfg->service_path || !cfg->service_path[0]) { return -1; }
    pid_t pid = fork();
    if (pid < 0) { return -1; }
    if (pid == 0) {
        execl(cfg->service_path, cfg->service_path, action, (char *)NULL);
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) { continue; }
        return -1;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static void telegram_config_flags(const d2k_panel_config *cfg,int *enabled,int *configured) {
    *enabled=0;*configured=0;
    if(!cfg||!cfg->config_path)return;
    FILE *f=fopen(cfg->config_path,"r");if(!f)return;
    char line[2048];int have_url=0,have_secret=0;
    while(fgets(line,sizeof(line),f)) {
        char *p=line;while(*p==' '||*p=='\t')p++;
        if(*p=='#'||!*p)continue;
        char *eq=strchr(p,'=');if(!eq)continue;*eq++='\0';
        char *end=p+strlen(p);while(end>p&&(end[-1]==' '||end[-1]=='\t'||end[-1]=='\r'||end[-1]=='\n'))*--end='\0';
        while(*eq==' '||*eq=='\t')eq++;
        end=eq+strlen(eq);while(end>eq&&(end[-1]==' '||end[-1]=='\t'||end[-1]=='\r'||end[-1]=='\n'))*--end='\0';
        if(strcmp(p,"TG_ENABLED")==0)*enabled=strcmp(eq,"1")==0||strcmp(eq,"yes")==0;
        else if(strcmp(p,"TG_RELAY_URL")==0)have_url=*eq!='\0';
        else if(strcmp(p,"TG_RELAY_SECRET")==0)have_secret=*eq!='\0';
    }
    fclose(f);*configured=have_url&&have_secret;
}

static void telegram_status_value(const d2k_panel_config *cfg,int enabled,int configured,int *running,char out[24]) {
    *running=cfg&&cfg->telegram_pid_path?pid_path_running(cfg->telegram_pid_path,NULL):0;
    const char *fallback=!configured?"not_configured":(!enabled||!*running?"stopped":"connecting");
    if(!configured||!enabled||!*running){snprintf(out,24,"%s",fallback);return;}
    int fd=cfg&&cfg->telegram_status_path?
        open(cfg->telegram_status_path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW):-1;
    if(fd<0){snprintf(out,24,"%s",fallback);return;}
    char buf[64];ssize_t n=read(fd,buf,sizeof(buf)-1);close(fd);
    if(n<=0){snprintf(out,24,"%s",fallback);return;}buf[n]='\0';
    char *end=buf+strlen(buf);while(end>buf&&(end[-1]=='\r'||end[-1]=='\n'||end[-1]==' '||end[-1]=='\t'))*--end='\0';
    if(strcmp(buf,"connected")==0||strcmp(buf,"connecting")==0||strcmp(buf,"stopped")==0||strcmp(buf,"not_configured")==0)
        snprintf(out,24,"%.23s",buf);
    else snprintf(out,24,"%s",fallback);
}

static int api_control(int fd, const d2k_panel_config *cfg, const char *req,
                       const char *path) {
    static const struct { const char *path; const char *command; const char *label; } actions[] = {
        { "/api/control/start", "engine-start", "Запуск движка" },
        { "/api/control/stop", "engine-stop", "Остановка движка" },
        { "/api/control/restart", "engine-restart", "Перезапуск движка" },
        { "/api/control/reapply", "reapply", "Восстановление правил" },
        { "/api/control/telegram-enable", "telegram-enable", "Включение Telegram-туннеля" },
        { "/api/control/telegram-disable", "telegram-disable", "Отключение Telegram-туннеля" },
    };
    const char *command = NULL, *label = NULL;
    for (size_t i = 0; i < sizeof actions / sizeof actions[0]; i++) {
        if (strcmp(path, actions[i].path) == 0) {
            command = actions[i].command;
            label = actions[i].label;
            break;
        }
    }
    if (!command) {
        static const char body[] = "{\"ok\":false,\"message\":\"Неизвестная операция\"}";
        return response(fd, 404, "Not Found", "application/json; charset=utf-8",
                        body, sizeof body - 1);
    }
    if (!cfg || !cfg->control_enabled || !same_origin(req)) {
        static const char body[] = "{\"ok\":false,\"message\":\"Управление разрешено только с этой панели\"}";
        return response(fd, 403, "Forbidden", "application/json; charset=utf-8",
                        body, sizeof body - 1);
    }
    if ((strcmp(command, "engine-start") == 0 ||
         strcmp(command, "engine-restart") == 0) &&
        cfg->mode && strcmp(cfg->mode, "off") == 0) {
        static const char body[] = "{\"ok\":false,\"message\":\"В config задан MODE=off; сначала измените режим движка\"}";
        return response(fd, 409, "Conflict", "application/json; charset=utf-8",
                        body, sizeof body - 1);
    }
    if(strcmp(command,"telegram-enable")==0) {
        int enabled=0,configured=0;telegram_config_flags(cfg,&enabled,&configured);(void)enabled;
        if(!configured) {
            static const char body[]="{\"ok\":false,\"message\":\"Сначала задайте TG_RELAY_URL и TG_RELAY_SECRET в конфигурации\"}";
            return response(fd,409,"Conflict","application/json; charset=utf-8",body,sizeof body-1);
        }
    }
    const char *transfer = NULL;
    size_t transfer_len = 0;
    if (header_value(req, "Transfer-Encoding", &transfer, &transfer_len)) {
        static const char body[] = "{\"ok\":false,\"message\":\"Тело запроса запрещено\"}";
        return response(fd, 400, "Bad Request", "application/json; charset=utf-8",
                        body, sizeof body - 1);
    }
    const char *length = NULL;
    size_t length_len = 0;
    if (header_value(req, "Content-Length", &length, &length_len) &&
        !(length_len == 1 && length[0] == '0')) {
        static const char body[] = "{\"ok\":false,\"message\":\"Тело запроса запрещено\"}";
        return response(fd, 400, "Bad Request", "application/json; charset=utf-8",
                        body, sizeof body - 1);
    }
    if (run_service_action(cfg, command) != 0) {
        static const char body[] = "{\"ok\":false,\"message\":\"Команда службы завершилась ошибкой\"}";
        return response(fd, 500, "Service Error", "application/json; charset=utf-8",
                        body, sizeof body - 1);
    }
    char body[256];
    int n = snprintf(body, sizeof body, "{\"ok\":true,\"action\":\"%s\",\"message\":\"Готово\"}", label);
    if (n < 0 || (size_t)n >= sizeof body) { return -1; }
    return response(fd, 200, "OK", "application/json; charset=utf-8", body, (size_t)n);
}

static int read_request(int fd, char *buf, size_t cap, size_t *used) {
    *used = 0;
    while (*used + 1 < cap) {
        ssize_t n = read(fd, buf + *used, cap - *used - 1);
        if (n < 0 && errno == EINTR) { continue; }
        if (n < 0) { return -1; }
        if (n == 0) { break; }
        *used += (size_t)n;
        buf[*used] = '\0';
        if (strstr(buf, "\r\n\r\n")) { return 0; }
    }
    return *used + 1 >= cap ? 1 : -1;
}

static int json_object_file(const char *path, char **out, size_t *out_len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { return -1; }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 1 ||
        (uint64_t)st.st_size > BODY_MAX) {
        close(fd);
        return -1;
    }
    size_t cap = (size_t)st.st_size;
    char *buf = malloc(cap + 1);
    if (!buf) { close(fd); return -1; }
    size_t nread = 0;
    while (nread < cap) {
        ssize_t n = read(fd, buf + nread, cap - nread);
        if (n < 0 && errno == EINTR) { continue; }
        if (n <= 0) { free(buf); close(fd); return -1; }
        nread += (size_t)n;
    }
    close(fd);
    buf[nread] = '\0';
    char *p = buf;
    char *end = buf + nread;
    if (!json_valid_object(p, end)) { free(buf); return -1; }
    *out = buf;
    *out_len = nread;
    return 0;
}

typedef struct {
    char *p;
    size_t len, cap;
    int failed;
} panel_buf;

static void buf_add(panel_buf *b, const char *s, size_t n) {
    if (b->failed || n > b->cap - b->len - 1) { b->failed = 1; return; }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
}

static void buf_puts(panel_buf *b, const char *s) { buf_add(b, s, strlen(s)); }

static void buf_printf(panel_buf *b, const char *fmt, ...) {
    if (b->failed) { return; }
    va_list ap, cp;
    va_start(ap, fmt);
    va_copy(cp, ap);
    int n = vsnprintf(NULL, 0, fmt, cp);
    va_end(cp);
    if (n < 0 || (size_t)n > b->cap - b->len - 1) {
        b->failed = 1;
        va_end(ap);
        return;
    }
    (void)vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap);
    b->len += (size_t)n;
    va_end(ap);
}

static void buf_json_string(panel_buf *b, const char *s) {
    const unsigned char *p = (const unsigned char *)(s ? s : "");
    buf_puts(b, "\"");
    for (; *p && !b->failed; p++) {
        char esc[7];
        if (*p == '"' || *p == '\\') {
            esc[0] = '\\'; esc[1] = (char)*p;
            buf_add(b, esc, 2);
        } else if (*p < 0x20) {
            (void)snprintf(esc, sizeof esc, "\\u%04x", (unsigned)*p);
            buf_add(b, esc, 6);
        } else {
            buf_add(b, (const char *)p, 1);
        }
    }
    buf_puts(b, "\"");
}

static void buf_live_knowledge(panel_buf *b, const char *json, size_t len,
                               int effective_linked) {
    const char *value = NULL;
    size_t value_len = 0;
    if (!json_top_value(json, "linked", &value, &value_len) ||
        value < json || (size_t)(value - json) > len ||
        value_len > len - (size_t)(value - json)) {
        buf_add(b, json, len);
        return;
    }
    size_t offset = (size_t)(value - json);
    buf_add(b, json, offset);
    buf_puts(b, effective_linked ? "true" : "false");
    size_t suffix_offset = offset + value_len;
    buf_add(b, json + suffix_offset, len - suffix_offset);
}

static void append_stage(panel_buf *b, const char *key, const char *title,
                         int built, const char *detail, int comma) {
    if (comma) { buf_puts(b, ","); }
    buf_puts(b, "{\"key\":"); buf_json_string(b, key);
    buf_puts(b, ",\"title\":"); buf_json_string(b, title);
    buf_printf(b, ",\"built\":%s,\"detail\":", built ? "true" : "false");
    buf_json_string(b, detail);
    buf_puts(b, "}");
}

static void append_snapshot(panel_buf *b, const d2k_panel_config *cfg,
                            int linked, int have_catalog, int live_fresh,
                            int engine_running, int controller_running) {
    time_t now = time(NULL);
    struct tm tmv;
    char now_iso[32], started_iso[32];
    if (gmtime_r(&now, &tmv)) { strftime(now_iso, sizeof now_iso, "%Y-%m-%dT%H:%M:%SZ", &tmv); }
    else { snprintf(now_iso, sizeof now_iso, "1970-01-01T00:00:00Z"); }
    long long started = cfg ? cfg->started_epoch : 0;
    time_t started_t = (time_t)started;
    if (started > 0 && gmtime_r(&started_t, &tmv)) {
        strftime(started_iso, sizeof started_iso, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    } else { snprintf(started_iso, sizeof started_iso, "0001-01-01T00:00:00Z"); }
    long long uptime = started > 0 && (long long)now > started ? (long long)now - started : 0;
    const char *cfg_path = cfg && cfg->config_path ? cfg->config_path : "/opt/d2k/config";
    const char *state_dir = cfg && cfg->state_dir ? cfg->state_dir : "/opt/d2k/state";
    const char *state_note = cfg && cfg->state_dir_note ? cfg->state_dir_note : "неизвестно";
    const char *mode = cfg && cfg->mode ? cfg->mode : "observe";
    const char *panel_listen = cfg && cfg->panel_listen ? cfg->panel_listen : "127.0.0.1:8090";
    int queue = cfg ? cfg->queue_num : 2000;
    int telegram_enabled=0,telegram_configured=0,telegram_running=0;char telegram_status[24];
    telegram_config_flags(cfg,&telegram_enabled,&telegram_configured);
    telegram_status_value(cfg,telegram_enabled,telegram_configured,&telegram_running,telegram_status);
    buf_puts(b, "{\"taken\":"); buf_json_string(b, now_iso);
    buf_puts(b, ",\"version\":"); buf_json_string(b, cfg ? cfg->version : "dev");
    buf_puts(b, ",\"commit\":"); buf_json_string(b, cfg ? cfg->commit : "");
    buf_puts(b, ",\"built\":"); buf_json_string(b, cfg ? cfg->built : "");
    buf_printf(b, ",\"dirty\":%s,\"config_path\":", cfg && cfg->dirty ? "true" : "false");
    buf_json_string(b, cfg_path);
    buf_printf(b, ",\"config_exists\":%s,\"mode\":", cfg && cfg->config_exists ? "true" : "false");
    buf_json_string(b, mode);
    buf_puts(b, ",\"panel_listen\":"); buf_json_string(b, panel_listen);
    buf_printf(b, ",\"controls_enabled\":%s", cfg && cfg->control_enabled ? "true" : "false");
    buf_printf(b, ",\"catalog_available\":%s", have_catalog ? "true" : "false");
    buf_printf(b, ",\"live_fresh\":%s", live_fresh ? "true" : "false");
    buf_printf(b, ",\"engine_running\":%s", engine_running ? "true" : "false");
    buf_printf(b, ",\"controller_running\":%s", controller_running ? "true" : "false");
    buf_printf(b, ",\"telegram_enabled\":%s,\"telegram_configured\":%s,\"telegram_running\":%s,\"telegram_status\":",
               telegram_enabled?"true":"false",telegram_configured?"true":"false",telegram_running?"true":"false");
    buf_json_string(b,telegram_status);
    buf_puts(b, ",\"state_dir\":"); buf_json_string(b, state_dir);
    buf_puts(b, ",\"state_dir_note\":"); buf_json_string(b, state_note);
    buf_printf(b, ",\"queue_num\":%d,\"unknown_keys\":[", queue);
    for (size_t i = 0; cfg && i < cfg->unknown_key_count; i++) {
        if (i) { buf_puts(b, ","); }
        buf_json_string(b, cfg->unknown_keys ? cfg->unknown_keys[i] : "");
    }
    buf_puts(b, "],\"started_at\":");
    buf_json_string(b, started_iso);
    buf_printf(b, ",\"uptime_seconds\":%lld,\"stages\":[", uptime);
    append_stage(b, "config", "Конфигурация", 1,
                 cfg && cfg->config_exists ? "Прочитана из конфигурационного файла." :
                 "Файла конфигурации нет, действуют умолчания.", 0);
    append_stage(b, "capture", "Чтение пакетов", linked,
                 linked ? "Очередь ядра открыта, пакеты читаются: контроллер получает события датапата." :
                          "Контроллер не подключён к датапату — сказать, читаются ли пакеты, нечем.", 1);
    append_stage(b, "flow", "Состояние потоков", linked,
                 linked ? "Датапат ведёт учёт соединений и сообщает о подозрениях." :
                          "Контроллер не подключён к датапату.", 1);
    append_stage(b, "plan", "Исполнение планов", linked,
                 linked ? "Планы ставятся датапату и исполняются на живых соединениях." :
                          "Контроллер не подключён к датапату: применяется ли обход, отсюда не видно.", 1);
    char boxes_detail[512];
    if (have_catalog) {
        snprintf(boxes_detail, sizeof boxes_detail, "Каталог открыт: изученные коробки и цели доступны.");
    } else { snprintf(boxes_detail, sizeof boxes_detail, "Каталог не открыт."); }
    append_stage(b, "boxes", "Каталог коробок", have_catalog, boxes_detail, 1);
    append_stage(b, "panel", "Панель", 1, "Показывает этот снимок.", 1);
    buf_puts(b, "],\"absent\":[");
    append_stage(b, "outages", "Здоровье наблюдения", 0,
                 "Нечем: сколько пакетов не дошло до очереди, снаружи не измеряется.", 0);
    if (!linked) {
        append_stage(b, "traffic", "Наблюдаемый трафик", 0,
                     "Нечем: контроллер не подключён к датапату. Это не «ноль соединений», а отсутствие измерения.", 1);
    }
    buf_puts(b, "]}");
}

static int api_status(int fd, const d2k_panel_config *cfg) {
    char *live = NULL;
    size_t live_len = 0;
    if (cfg && cfg->live_path && json_object_file(cfg->live_path, &live, &live_len) == 0) {
        size_t cap = live_len + 16384;
        char *body = malloc(cap);
        if (!body) { free(live); return -1; }
        panel_buf b = { .p = body, .len = 0, .cap = cap, .failed = 0 };
        buf_puts(&b, "{\"snapshot\":");
        time_t now = time(NULL);
        struct stat live_stat;
        time_t engine_started_at = 0;
        int engine_running = engine_pid_running(cfg, &engine_started_at);
        int controller_running = controller_pid_running(cfg);
        int live_fresh = cfg->live_path && stat(cfg->live_path, &live_stat) == 0 &&
            S_ISREG(live_stat.st_mode) &&
            (!engine_started_at || live_stat.st_mtime >= engine_started_at) &&
            (live_stat.st_mtime > now ? live_stat.st_mtime - now <= 5 :
                                         now - live_stat.st_mtime <= 15);
        int linked = json_top_true(live, "linked") && live_fresh &&
                     engine_running && controller_running;
        int have_catalog = json_top_nonempty_string(live, "catalog_at");
        append_snapshot(&b, cfg, linked, have_catalog, live_fresh,
                        engine_running, controller_running);
        buf_puts(&b, ",\"knowledge\":");
        buf_live_knowledge(&b, live, live_len, linked);
        buf_puts(&b, "}");
        if (b.failed) { free(body); free(live); return -1; }
        int rc = response(fd, 200, "OK", "application/json; charset=utf-8",
                          body, b.len);
        free(body);
        free(live);
        return rc;
    }
    static const char unavailable_knowledge[] =
        "{\"linked\":false,\"link_note\":\"движок не отдаёт состояние\","
        "\"catalog_at\":\"\",\"boxes\":[],\"searches\":[],\"targets\":0,"
        "\"confirms\":0,\"probes_used\":0,\"client_unfit\":0}";
    size_t cap = 16384;
    char *body = malloc(cap);
    if (!body) { return -1; }
    panel_buf b = { .p = body, .len = 0, .cap = cap, .failed = 0 };
    buf_puts(&b, "{\"snapshot\":");
    append_snapshot(&b, cfg, 0, 0, 0, engine_pid_running(cfg, NULL),
                    controller_pid_running(cfg));
    buf_puts(&b, ",\"knowledge\":");
    buf_puts(&b, unavailable_knowledge);
    buf_puts(&b, "}");
    int rc = b.failed ? -1 : response(fd, 200, "OK", "application/json; charset=utf-8", body, b.len);
    free(body);
    return rc;
}

static int static_file(int fd, const d2k_panel_config *cfg, const char *name,
                       const char *type) {
    if (!cfg || !cfg->asset_dir) {
        return response(fd, 404, "Not Found", "text/plain; charset=utf-8", "not found\n", 10);
    }
    int dirfd = open(cfg->asset_dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (dirfd < 0) {
        return response(fd, 404, "Not Found", "text/plain; charset=utf-8", "not found\n", 10);
    }
    int in = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    close(dirfd);
    if (in < 0) {
        return response(fd, 404, "Not Found", "text/plain; charset=utf-8", "not found\n", 10);
    }
    struct stat st;
    if (fstat(in, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uint64_t)st.st_size > BODY_MAX) {
        close(in);
        return response(fd, 404, "Not Found", "text/plain; charset=utf-8", "not found\n", 10);
    }
    size_t cap = (size_t)st.st_size;
    char *body = malloc(cap ? cap : 1);
    if (!body) { close(in); return -1; }
    size_t got = 0;
    while (got < cap) {
        ssize_t nr = read(in, body + got, cap - got);
        if (nr < 0 && errno == EINTR) { continue; }
        if (nr <= 0) { free(body); close(in); return -1; }
        got += (size_t)nr;
    }
    close(in);
    int rc = response(fd, 200, "OK", type, body, cap);
    free(body);
    return rc;
}

int d2k_panel_handle_fd(int fd, const d2k_panel_config *cfg) {
    char req[REQUEST_MAX + 1];
    size_t used = 0;
    int rr = read_request(fd, req, sizeof req, &used);
    if (rr != 0) {
        static const char too_large[] = "request too large\n";
        return response(fd, rr > 0 ? 431 : 400,
                        rr > 0 ? "Request Header Fields Too Large" : "Bad Request",
                        "text/plain; charset=utf-8", too_large, sizeof too_large - 1);
    }
    char method[8], path[256], version[16];
    if (sscanf(req, "%7s %255s %15s", method, path, version) != 3 ||
        (strcmp(version, "HTTP/1.1") != 0 && strcmp(version, "HTTP/1.0") != 0)) {
        return response(fd, 400, "Bad Request", "text/plain; charset=utf-8", "bad request\n", 12);
    }
    char *query = strchr(path, '?');
    if (query) { *query = '\0'; }
    if (strncmp(path, "/api/control/", sizeof "/api/control/" - 1) == 0) {
        if (strcmp(method, "POST") != 0) {
            return response(fd, 405, "Method Not Allowed", "text/plain; charset=utf-8",
                            "method not allowed\n", 19);
        }
        return api_control(fd, cfg, req, path);
    }
    if (strcmp(method, "GET") != 0) {
        return response(fd, 405, "Method Not Allowed", "text/plain; charset=utf-8", "method not allowed\n", 19);
    }
    if (strcmp(path, "/api/status") == 0) { return api_status(fd, cfg); }
    if (strcmp(path, "/") == 0) {
        return static_file(fd, cfg, "index.html", "text/html; charset=utf-8");
    }
    if (strcmp(path, "/assets/panel.css") == 0) {
        return static_file(fd, cfg, "panel.css", "text/css; charset=utf-8");
    }
    if (strcmp(path, "/assets/panel.js") == 0) {
        return static_file(fd, cfg, "panel.js", "application/javascript; charset=utf-8");
    }
    if (strcmp(path, "/assets/mascot.svg") == 0) {
        return static_file(fd, cfg, "mascot.svg", "image/svg+xml; charset=utf-8");
    }
    if (strcmp(path, "/assets/logo-d2k.png") == 0) {
        return static_file(fd, cfg, "logo-d2k.png", "image/png");
    }
    if (strcmp(path, "/assets/mascot-d2k.png") == 0) {
        return static_file(fd, cfg, "mascot-d2k.png", "image/png");
    }
    (void)used;
    return response(fd, 404, "Not Found", "text/plain; charset=utf-8", "not found\n", 10);
}
