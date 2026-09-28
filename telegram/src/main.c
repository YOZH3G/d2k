#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L
#include "tg_config.h"
#include "tg_identity.h"
#include "tg_net.h"
#include "tg_register.h"
#include "tg_enroll.h"
#include "tg_session.h"
#include "tg_tunnel.h"
#include "tg_tls.h"
#include "tg_ws.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define TG_BUILD "d2k-tg-0.2"
#define TG_DEFAULT_WINDOW (2u*1024u*1024u)

static volatile sig_atomic_t stop_requested;

static void on_signal(int signo) { (void)signo;stop_requested=1; }

static void log_msg(const char *message) {
    time_t now=time(NULL);struct tm tmv;char stamp[32]="unknown-time";
    if(localtime_r(&now,&tmv))strftime(stamp,sizeof(stamp),"%Y-%m-%d %H:%M:%S",&tmv);
    fprintf(stderr,"%s d2ktg: %s\n",stamp,message);fflush(stderr);
}

static int write_status(const char *path,const char *value) {
    char tmp[600];if(!path||!*path||snprintf(tmp,sizeof(tmp),"%s.tmp.%ld",path,(long)getpid())>=(int)sizeof(tmp))return -1;
    int fd=open(tmp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0644);if(fd<0)return -1;
    size_t len=strlen(value);ssize_t n=write(fd,value,len);int ok=n==(ssize_t)len&&fsync(fd)==0;
    if(close(fd)!=0)ok=0;if(!ok||rename(tmp,path)!=0){unlink(tmp);return -1;}return 0;
}

static int create_listener(uint16_t port) {
    int fd=socket(AF_INET,SOCK_STREAM,0),one=1;if(fd<0)return -1;
    struct sockaddr_in addr={.sin_family=AF_INET,.sin_port=htons(port),.sin_addr={.s_addr=htonl(INADDR_ANY)}};
    int flags=fcntl(fd,F_GETFL,0);
    if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK)!=0||
       setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one))!=0||
       bind(fd,(struct sockaddr *)&addr,sizeof(addr))!=0||listen(fd,256)!=0){close(fd);return -1;}
    return fd;
}

typedef struct { SSL *ssl; } session_transport;
static int session_send(void *opaque,const uint8_t *data,size_t len) {
    session_transport *t=opaque;return tg_ws_write_binary(t->ssl,data,len);
}
static int session_read(void *opaque,uint8_t *dst,size_t cap,size_t *len) {
    session_transport *t=opaque;int rc=tg_ws_read_binary(t->ssl,dst,cap,len);return rc==0?0:-1;
}

static int establish_ws(SSL_CTX *ctx,const tg_relay_url *url,SSL **out_ssl,int *out_fd) {
    int fd=tg_tcp_connect_ipv4(url->host,url->port,10000);if(fd<0)return -1;
    SSL *ssl=tg_tls_connect_fd(ctx,fd,url->host);
    if(!ssl){close(fd);return -1;}
    char host_header[320];int n=snprintf(host_header,sizeof(host_header),"%s:%u",url->host,(unsigned)url->port);
    if(n<=0||(size_t)n>=sizeof(host_header)||tg_ws_upgrade(ssl,host_header,url->path)!=0){SSL_free(ssl);close(fd);return -1;}
    *out_ssl=ssl;*out_fd=fd;return 0;
}

static void close_ws(SSL **ssl,int *fd) {
    if(*ssl){SSL_free(*ssl);*ssl=NULL;}if(*fd>=0){close(*fd);*fd=-1;}
}

static int register_identity(const tg_config *cfg,const tg_relay_url *url,tg_identity *identity) {
    if(!cfg->relay_secret[0])return tg_enroll_identity(url->host,cfg->enroll_port,cfg->ca_bundle,identity);
    return tg_register_identity(url->host,url->port,url->host,cfg->ca_bundle,cfg->relay_secret,identity);
}

static int ensure_registered(const tg_config *cfg,const tg_relay_url *url,tg_identity *identity) {
    int rc=register_identity(cfg,url,identity);
    if(rc!=TG_REGISTER_ID_CONFLICT)return rc;
    log_msg("relay reports an identity conflict; rotating the local installation identity");
    tg_identity_cleanup(identity);
    if(unlink(cfg->identity_path)!=0&&errno!=ENOENT)return -1;
    if(tg_identity_load_or_mint(cfg->identity_path,identity)!=0)return -1;
    return register_identity(cfg,url,identity);
}

static void interruptible_wait(uint32_t delay_ms) {
    struct timespec req={.tv_sec=(time_t)(delay_ms/1000u),.tv_nsec=(long)(delay_ms%1000u)*1000000L};
    while(!stop_requested&&nanosleep(&req,&req)!=0&&errno==EINTR){}
}

static double random_unit(void) {
    uint64_t value=0;if(RAND_bytes((unsigned char *)&value,sizeof(value))!=1)return 0.5;
    return (double)value/(double)UINT64_MAX;
}

static int run_daemon(const char *config_path) {
    tg_config cfg;tg_relay_url url;tg_identity identity={0};SSL_CTX *ctx=NULL;int listener=-1,rc=1;
    if(tg_config_read(config_path,&cfg)!=0){log_msg("cannot read configuration");return 1;}
    if(!cfg.enabled||!cfg.relay_url[0]||(!cfg.relay_secret[0]&&!cfg.enroll_port)){
        (void)write_status(cfg.status_path,"not_configured\n");tg_config_clean(&cfg);return 0;
    }
    if(tg_relay_url_parse(cfg.relay_url,&url)!=0){log_msg("TG_RELAY_URL must be a valid wss://host[:port]/ws URL");(void)write_status(cfg.status_path,"error\n");goto done;}
    ctx=tg_tls_client_context(cfg.ca_bundle);if(!ctx){log_msg("cannot load Telegram relay trust bundle");(void)write_status(cfg.status_path,"error\n");goto done;}
    if(tg_identity_load_or_mint(cfg.identity_path,&identity)!=0){log_msg("cannot load or create the per-install relay identity");(void)write_status(cfg.status_path,"error\n");goto done;}
    listener=create_listener(cfg.listen_port);if(listener<0){log_msg("cannot bind the Telegram redirect listener");(void)write_status(cfg.status_path,"error\n");goto done;}
    struct sigaction sa;memset(&sa,0,sizeof(sa));sa.sa_handler=on_signal;sigemptyset(&sa.sa_mask);
    (void)sigaction(SIGINT,&sa,NULL);(void)sigaction(SIGTERM,&sa,NULL);(void)signal(SIGPIPE,SIG_IGN);

    unsigned failures=0,fast_deaths=0;int healthy=0,identity_registered=0;
    while(!stop_requested) {
        (void)write_status(cfg.status_path,"connecting\n");
        if(!identity_registered) {
            int registered=ensure_registered(&cfg,&url,&identity);
            if(registered!=0){log_msg("relay identity registration failed; will retry");failures++;
                interruptible_wait(tg_reconnect_delay_ms(failures,0,healthy,random_unit()));continue;}
            identity_registered=1;
        }
        SSL *ssl=NULL;int relay_fd=-1;int protocol_v2=1;uint32_t window=TG_DEFAULT_WINDOW;
        if(establish_ws(ctx,&url,&ssl,&relay_fd)!=0){log_msg("verified relay WSS connection failed; will retry");failures++;
            interruptible_wait(tg_reconnect_delay_ms(failures,0,healthy,random_unit()));continue;}
        session_transport transport={.ssl=ssl};tg_session_io io={.ctx=&transport,.send_binary=session_send,.read_binary=session_read};
        tg_session_state session={0};time_t began=time(NULL);
        int auth=tg_session_authenticate_v2(&io,&identity,TG_BUILD,(int64_t)began,&session);
        if(auth==TG_SESSION_FALLBACK_V1) {
            close_ws(&ssl,&relay_fd);
            if(establish_ws(ctx,&url,&ssl,&relay_fd)!=0){log_msg("could not reconnect for the explicit v1 protocol fallback");failures++;
                interruptible_wait(tg_reconnect_delay_ms(failures,0,healthy,random_unit()));continue;}
            transport.ssl=ssl;protocol_v2=0;
            if(tg_session_authenticate_v1(&io,&identity,(int64_t)time(NULL))!=0){log_msg("v1 identity authentication failed");close_ws(&ssl,&relay_fd);failures++;
                interruptible_wait(tg_reconnect_delay_ms(failures,0,healthy,random_unit()));continue;}
            window=0;
        } else if(auth!=TG_SESSION_V2_OK) {
            log_msg("relay authentication failed; no protocol fallback is attempted");close_ws(&ssl,&relay_fd);failures++;fast_deaths++;
            if(tg_reconnect_needs_reregister(fast_deaths)){int rer=ensure_registered(&cfg,&url,&identity);fast_deaths=0;identity_registered=rer==0;if(rer!=0)log_msg("identity re-registration after repeated fast failures failed");}
            interruptible_wait(tg_reconnect_delay_ms(failures,session.retry_after,healthy,random_unit()));continue;
        } else if(session.window)window=session.window;
        (void)write_status(cfg.status_path,"connected\n");log_msg(protocol_v2?"relay session authenticated (mux v2)":"relay session authenticated (mux v1)");
        tg_tunnel_config tunnel={.relay_ssl=ssl,.listener_fd=listener,.listen_port=cfg.listen_port,
            .protocol_v2=protocol_v2,.window=window,.stop=&stop_requested};
        int tunnel_rc=tg_tunnel_run(&tunnel);close_ws(&ssl,&relay_fd);
        time_t lifetime=time(NULL)-began;
        if(lifetime>=60){healthy=1;failures=0;fast_deaths=0;}
        else {healthy=0;failures++;fast_deaths++;}
        if(tg_reconnect_needs_reregister(fast_deaths)){int rer=ensure_registered(&cfg,&url,&identity);fast_deaths=0;identity_registered=rer==0;if(rer!=0)log_msg("identity re-registration after repeated fast session deaths failed");}
        if(!stop_requested){
            if(tunnel_rc<0)log_msg("relay session ended; reconnecting");
            (void)write_status(cfg.status_path,"connecting\n");
            interruptible_wait(tg_reconnect_delay_ms(failures,0,healthy,random_unit()));
        }
    }
    (void)write_status(cfg.status_path,"stopped\n");rc=0;
done:
    if(listener>=0)close(listener);if(ctx)SSL_CTX_free(ctx);tg_identity_cleanup(&identity);tg_config_clean(&cfg);return rc;
}

static int check_config(const char *path) {
    tg_config cfg;tg_relay_url url;
    int ok=tg_config_read(path,&cfg)==0;
    if(ok)ok=(cfg.relay_secret[0]||cfg.enroll_port)&&cfg.relay_url[0]&&access(cfg.ca_bundle,R_OK)==0&&
        tg_relay_url_parse(cfg.relay_url,&url)==0;
    tg_config_clean(&cfg);return ok?0:1;
}

static int redirect_log(const char *path) {
    if(!path||!*path)return 0;
    int fd=open(path,O_WRONLY|O_CREAT|O_APPEND|O_NOFOLLOW,0644);if(fd<0)return -1;
    if(dup2(fd,STDERR_FILENO)<0){close(fd);return -1;}close(fd);return 0;
}

int main(int argc,char **argv) {
    const char *config="/opt/d2k/config",*log_path=NULL;
    if(argc==2&&strcmp(argv[1],"--version")==0){puts(TG_BUILD " features=per-install-enrollment");return 0;}
    if(argc==2&&strcmp(argv[1],"--help")==0){puts("d2ktg [--config FILE]");return 0;}
    if(argc==3&&strcmp(argv[1],"--check-config")==0)return check_config(argv[2]);
    for(int i=1;i<argc;i++) {
        if(strcmp(argv[i],"--config")==0&&i+1<argc)config=argv[++i];
        else if(strcmp(argv[i],"--log")==0&&i+1<argc)log_path=argv[++i];
        else {fprintf(stderr,"usage: d2ktg [--config FILE] [--log FILE]\n");return 2;}
    }
    if(redirect_log(log_path)!=0){fprintf(stderr,"d2ktg: cannot open configured log file\n");return 1;}
    return run_daemon(config);
}
