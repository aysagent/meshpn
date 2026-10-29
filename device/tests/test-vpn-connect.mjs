// Execute production TCP/UDP connection setup with failures from socket APIs.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const production = fs.readFileSync(new URL('../components/meshvpn_vpn/meshvpn_vpn.c', import.meta.url), 'utf8');
const begin = production.indexOf('static int connect_exit(');
const end = production.indexOf('static void socket_failure(', begin);
if (begin < 0 || end < begin) throw Error('Production connect missing');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'meshpn-vpn-connect-'));
const source = `
#define _DEFAULT_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#ifndef TCP_KEEPIDLE
#define TCP_KEEPIDLE 100
#endif
#define ESP_OK 0
typedef int esp_err_t;
typedef void esp_tls_t;
typedef int esp_netif_t;
typedef struct { struct { uint32_t addr; } ip; } esp_netif_ip_info_t;
typedef struct { char transport[16],server[32],tls_server_name[64]; uint32_t generation; } meshvpn_vpn_status_t;
static enum { SUCCESS, GETFLAGS, SETFLAGS, BIND, SELECT, SOCKOPT, SOERROR, TIMEOUT, CANCEL, INTERRUPT } scenario;
static unsigned closed, connects, selects;
static esp_netif_t netif;
static esp_netif_t *esp_netif_get_handle_from_ifkey(const char *key) { (void)key;return &netif; }
static bool esp_netif_is_netif_up(esp_netif_t *n) { (void)n;return true; }
static esp_err_t esp_netif_get_ip_info(esp_netif_t *n,esp_netif_ip_info_t *ip) { (void)n;ip->ip.addr=1;return ESP_OK; }
static esp_err_t esp_netif_get_netif_impl_name(esp_netif_t *n,char *p) { (void)n;strcpy(p,"st0");return ESP_OK; }
static bool plain_transport(const char *p) { (void)p;return true; }
static bool meshvpn_vpn_endpoint(const char *s,uint8_t *ip,uint16_t *port) { (void)s;memset(ip,1,4);*port=8765;return true; }
static esp_err_t meshvpn_vpn_tls_connect(const char *s,const char *name,const char *iface,esp_tls_t **tls,int *fd) {
 (void)s;(void)name;(void)iface;(void)tls;(void)fd;assert(false);return -1;
}
static void state(uint32_t g,const char *name,bool up,int e) { (void)g;(void)name;(void)up;(void)e; }
static bool session(uint32_t g) { assert(g==7);return scenario!=CANCEL || !selects; }
static int sock(int family,int type,int protocol) { (void)protocol;assert(family==AF_INET && (type==SOCK_STREAM||type==SOCK_DGRAM));return 42; }
static int bind_sock(int fd,const struct sockaddr *a,socklen_t n) {
 (void)a;(void)n;assert(fd==42);if(scenario==BIND){errno=EADDRNOTAVAIL;return -1;}return 0;
}
static int flags_sock(int fd,int cmd,int flags) {
 assert(fd==42);
 if(scenario==GETFLAGS && cmd==F_GETFL){errno=EBADF;return -1;}
 if(scenario==SETFLAGS && cmd==F_SETFL){errno=EINVAL;return -1;}
 if(cmd==F_GETFL)return O_APPEND;
 assert(cmd==F_SETFL && flags==(O_APPEND|O_NONBLOCK));return 0;
}
static int set_opt(int fd,int level,int opt,const void *v,socklen_t n) { (void)fd;(void)level;(void)opt;(void)v;(void)n;return 0; }
static int connect_sock(int fd,const struct sockaddr *a,socklen_t n) { (void)a;(void)n;assert(fd==42);connects++;errno=EINPROGRESS;return -1; }
static int select_sock(int n,fd_set *r,fd_set *w,fd_set *e,struct timeval *t) {
 (void)n;(void)r;(void)w;(void)e;assert(t->tv_usec==100000);selects++;
 if(scenario==SELECT){errno=EBADF;return -1;}
 if(scenario==INTERRUPT && selects==1){errno=EINTR;return -1;}
 return scenario==TIMEOUT||scenario==CANCEL?0:1;
}
static int get_opt(int fd,int level,int opt,void *value,socklen_t *n) {
 (void)level;assert(fd==42 && opt==SO_ERROR && *n==sizeof(int));
 if(scenario==SOCKOPT){errno=ENOBUFS;return -1;}
 *(int *)value=scenario==SOERROR?ECONNREFUSED:0;return 0;
}
static int close_sock(int fd) { assert(fd==42);closed++;errno=EIO;return 0; }
#define socket sock
#define bind bind_sock
#define fcntl flags_sock
#define setsockopt set_opt
#define connect connect_sock
#define select select_sock
#define getsockopt get_opt
#define close close_sock
${production.slice(begin,end)}
static void run(int which,int error,const char *transport) {
 scenario=which;closed=connects=selects=0;errno=0;
 meshvpn_vpn_status_t cfg={.generation=7};strcpy(cfg.transport,transport);
 esp_tls_t *tls=(void *)1;int fd=connect_exit(&cfg,&tls);assert(!tls);
 if(error) {assert(fd==-1 && errno==error && closed==1);}
 else {assert(fd==42 && !closed);}
 if(which==GETFLAGS||which==SETFLAGS||which==BIND)assert(!connects);
 if(which==SELECT||which==SOCKOPT||which==CANCEL)assert(selects==1);
 if(which==TIMEOUT)assert(selects==50);
}
int main(void) {
 run(SUCCESS,0,"tcp");run(INTERRUPT,0,"tcp");
 run(GETFLAGS,EBADF,"tcp");run(SETFLAGS,EINVAL,"tcp");run(SETFLAGS,EINVAL,"udp");
 run(BIND,EADDRNOTAVAIL,"tcp");run(SELECT,EBADF,"tcp");
 run(SOCKOPT,ENOBUFS,"tcp");run(SOERROR,ECONNREFUSED,"tcp");
 run(TIMEOUT,ETIMEDOUT,"tcp");run(CANCEL,ECANCELED,"tcp");
 puts("VPN connect: nonblocking setup, errno preservation, select interruption, timeout and cancellation passed");
}
`;
const file=path.join(dir,'test.c'), binary=path.join(dir,'test');
fs.writeFileSync(file,source);
execFileSync(process.env.CC||'cc',['-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',file,'-o',binary],{stdio:'inherit'});
execFileSync(binary,[],{stdio:'inherit'});
