#include "meshvpn_net_bench.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include "esp_heap_caps.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "meshvpn_vpn.h"

/* Wire protocol: 32-byte hello: MNB1, nonce, download (0/1), seconds,
 * kbps, payload bytes (1200 UDP / 8192 TCP), reserved zero, reserved zero.
 * All words big endian. Peer echoes hello before data. UDP data: MND1,
 * nonce, sequence, padding. Receipt counters exclude hello. */
static portMUX_TYPE lock = portMUX_INITIALIZER_UNLOCKED;
static meshvpn_net_bench_result_t result;
static meshvpn_net_bench_config_t config;
static bool cancelled;
static uint64_t now(void) { return esp_timer_get_time(); }
static void put(uint8_t *p, uint32_t n) { n=htonl(n); memcpy(p,&n,4); }
static uint32_t get(const uint8_t *p) { uint32_t n;memcpy(&n,p,4);return ntohl(n); }
/* 32 Mbit/s * 60 s / 1200 bytes is at most 200000 packets. Keep a
 * bounded bitmap in PSRAM only while receiving a UDP test. Never turn an
 * untrusted sequence number into an unbounded allocation or array index. */
#define UDP_SEQUENCE_LIMIT 250000u
#define UDP_SEEN_BYTES ((UDP_SEQUENCE_LIMIT + 7u) / 8u)
static bool accept_udp(const uint8_t *data, size_t n, uint8_t *seen,
                       meshvpn_net_bench_result_t *r)
{
    if(n!=1200||memcmp(data,"MND1",4)||get(data+4)!=r->nonce) {r->invalid++;return false;}
    uint32_t seq=get(data+8);
    if(seq>=UDP_SEQUENCE_LIMIT){r->invalid++;return false;}
    uint8_t bit=(uint8_t)(1u<<(seq%8));
    if(seen[seq/8]&bit){r->duplicates++;return false;}
    seen[seq/8]|=bit;
    if(seq<r->sequence_span)r->reordered++;
    else r->sequence_span=seq+1;
    return true;
}
static bool stopping(void)
{
    portENTER_CRITICAL(&lock); bool stop=cancelled; portEXIT_CRITICAL(&lock);
    return stop || meshvpn_vpn_is_enabled();
}
static void publish(const meshvpn_net_bench_result_t *r)
{ portENTER_CRITICAL(&lock);result=*r;portEXIT_CRITICAL(&lock); }
void meshvpn_net_bench_status(meshvpn_net_bench_result_t *r)
{ portENTER_CRITICAL(&lock);*r=result;portEXIT_CRITICAL(&lock); }
void meshvpn_net_bench_cancel(void)
{ portENTER_CRITICAL(&lock);cancelled=true;portEXIT_CRITICAL(&lock); }
static int ready(int fd,bool write,uint64_t deadline)
{
    while(now()<deadline && !stopping()) {
        fd_set set;FD_ZERO(&set);FD_SET(fd,&set);
        struct timeval timeout={.tv_usec=100000};
        int n=select(fd+1,write?NULL:&set,write?&set:NULL,NULL,&timeout);
        if(n>0)return 1;
        if(n<0 && errno!=EINTR)return -1;
    }
    errno=stopping()?ECANCELED:ETIMEDOUT;return -1;
}
static int exchange(int fd,uint8_t *p,size_t n,bool write,bool udp,uint64_t end)
{
    size_t pos=0;
    while(pos<n) {
        if(ready(fd,write,end)<0)return -1;
        int k=write?send(fd,p+pos,n-pos,0):recv(fd,p+pos,n-pos,0);
        if(k<0 && (errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))continue;
        if(k<=0){if(!k)errno=ECONNRESET;return -1;}
        if(udp && (size_t)k!=n){errno=EPROTO;return -1;}
        pos+=k;
    }
    return 0;
}
static void worker(void *unused)
{
    (void)unused;
    meshvpn_net_bench_config_t c=config;
    meshvpn_net_bench_result_t r={.running=true,.nonce=c.nonce,.udp_sequence_available=c.udp&&c.download};
    int fd=-1;uint8_t *buffer=heap_caps_malloc(8192,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    uint8_t *seen=r.udp_sequence_available?heap_caps_calloc(1,UDP_SEEN_BYTES,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT):NULL;
    esp_netif_t *sta=esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t info;
    if(!buffer||(r.udp_sequence_available&&!seen)){r.error=ENOMEM;goto done;}
    if(!sta||!esp_netif_is_netif_up(sta)||esp_netif_get_ip_info(sta,&info)!=ESP_OK||!info.ip.addr){r.error=ENETDOWN;goto done;}
    r.source=info.ip.addr;publish(&r);
    fd=socket(AF_INET,c.udp?SOCK_DGRAM:SOCK_STREAM,0);
    if(fd<0){r.error=errno;goto done;}
    struct ifreq iface={0};
    if(esp_netif_get_netif_impl_name(sta,iface.ifr_name)!=ESP_OK ||
       setsockopt(fd,SOL_SOCKET,SO_BINDTODEVICE,&iface,sizeof(iface))<0){r.error=ENODEV;goto done;}
    struct sockaddr_in local={.sin_family=AF_INET,.sin_addr.s_addr=r.source};
    if(bind(fd,(struct sockaddr *)&local,sizeof(local))<0||fcntl(fd,F_SETFL,O_NONBLOCK)<0){r.error=errno;goto done;}
    struct sockaddr_in peer={.sin_family=AF_INET,.sin_port=htons(c.port),.sin_addr.s_addr=c.target};
    uint64_t end=now()+5000000;
    if(connect(fd,(struct sockaddr *)&peer,sizeof(peer))<0) {
        if(errno!=EINPROGRESS||ready(fd,true,end)<0){r.error=errno;goto done;}
        int e=0;socklen_t size=sizeof(e);
        if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&e,&size)<0||e){r.error=e?e:errno;goto done;}
    }
    uint8_t hello[32]={0};memcpy(hello,"MNB1",4);put(hello+4,c.nonce);put(hello+8,c.download);
    put(hello+12,c.seconds);put(hello+16,c.rate_kbps);put(hello+20,c.udp?1200:8192);
    memcpy(buffer,hello,32);
    if(exchange(fd,buffer,32,true,c.udp,end)<0||exchange(fd,buffer,32,false,c.udp,end)<0){r.error=errno;goto done;}
    if(memcmp(hello,buffer,32)){r.error=EPROTO;goto done;}
    memset(buffer,0x5a,8192);memcpy(buffer,"MND1",4);put(buffer+4,c.nonce);
    uint64_t start=now(), report=start, next=start;
    end=start+(uint64_t)c.seconds*1000000;
    size_t length=c.udp?1200:8192;
    while(now()<end && !stopping()) {
        if(!esp_netif_is_netif_up(sta)){r.error=ENETDOWN;break;}
        if(!c.download && c.udp && now()<next) {vTaskDelay(1);continue;}
        if(ready(fd,!c.download,end)<0){if(errno!=ETIMEDOUT)r.error=errno;break;}
        if(!c.download && c.udp)put(buffer+8,r.packets);
        int n=c.download?recv(fd,buffer,8192,0):send(fd,buffer,length,0);
        if(n<0 && (errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR)){r.stalls++;continue;}
        if(n<=0){if(n<0)r.error=errno;break;}
        if(c.udp && c.download && !accept_udp(buffer,(size_t)n,seen,&r))continue;
        if(c.udp && !c.download && n!=1200){r.error=EPROTO;break;}
        r.bytes+=n;r.packets++;
        if(c.udp && !c.download)next=start+r.bytes*8000/c.rate_kbps;
        r.elapsed_us=now()-start;
        if(now()-report>=100000){publish(&r);report=now();}
    }
    r.elapsed_us=now()-start;
    if(stopping())r.error=ECANCELED;
 done:
    if(fd>=0)close(fd);
    free(seen);free(buffer);r.running=false;publish(&r);vTaskDelete(NULL);
}
esp_err_t meshvpn_net_bench_start(const meshvpn_net_bench_config_t *c)
{
    if(!c)return ESP_ERR_INVALID_ARG;
    uint32_t ip=ntohl(c->target);
    bool private_ip=(ip>>24)==10||(ip>>20)==0xac1||(ip>>16)==0xc0a8;
    if(!private_ip||!(ip&255)||(ip&255)==255||!c->nonce||c->port<1024||
       c->seconds<1||c->seconds>60||c->rate_kbps<64||c->rate_kbps>32000)return ESP_ERR_INVALID_ARG;
    if(meshvpn_vpn_is_enabled())return ESP_ERR_INVALID_STATE;
    portENTER_CRITICAL(&lock);
    if(result.running){portEXIT_CRITICAL(&lock);return ESP_ERR_INVALID_STATE;}
    config=*c;cancelled=false;result=(meshvpn_net_bench_result_t){.running=true,.nonce=c->nonce};
    portEXIT_CRITICAL(&lock);
    if(xTaskCreate(worker,"net_bench",6144,NULL,4,NULL)!=pdPASS){
        portENTER_CRITICAL(&lock);result.running=false;result.error=ENOMEM;portEXIT_CRITICAL(&lock);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
