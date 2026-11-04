// Linux IPv4 multicast companion to Avahi: no separate name ownership/probing.
// Avahi remains responsible for A records and gates replies after establishment.
#include "mdns-negative.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

static int negative_fd=-1, established;
static AvahiWatch *negative_watch;
static struct in_addr negative_source;
static uint8_t negative_packet[512];
static size_t negative_length;
static double negative_last;
static void negative_read(AvahiWatch *watch,int fd,AvahiWatchEvent event,void *data) {
 (void)watch;(void)event;(void)data;
 for(unsigned batch=0;batch<16;batch++) {
  uint8_t packet[4096];
  union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(struct in_pktinfo))+CMSG_SPACE(sizeof(int))]; } control;
  struct sockaddr_in peer={0};struct iovec io={packet,sizeof packet};
  struct msghdr msg={.msg_name=&peer,.msg_namelen=sizeof peer,.msg_iov=&io,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof control.bytes};
  ssize_t n=recvmsg(fd,&msg,MSG_DONTWAIT);if(n<0){if(errno==EINTR)continue;return;}
  int incoming=0,ttl=0;
  for(struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c;c=CMSG_NXTHDR(&msg,c)) {
   if(c->cmsg_level!=IPPROTO_IP)continue;
   if(c->cmsg_type==IP_PKTINFO&&c->cmsg_len>=CMSG_LEN(sizeof(struct in_pktinfo)))incoming=((struct in_pktinfo *)CMSG_DATA(c))->ipi_ifindex;
   if(c->cmsg_type==IP_TTL&&c->cmsg_len>=CMSG_LEN(sizeof(int)))memcpy(&ttl,CMSG_DATA(c),sizeof ttl);
  }
  if(!established||(msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC))||incoming!=iface||ttl!=255||peer.sin_port!=htons(5353)||!mdns_asks_aaaa(packet,(size_t)n,hostname))continue;
  struct timespec now;if(clock_gettime(CLOCK_MONOTONIC,&now)<0)return;
  double seconds=now.tv_sec+now.tv_nsec/1e9;if(seconds-negative_last<1)continue;
  struct sockaddr_in dest={.sin_family=AF_INET,.sin_port=htons(5353),.sin_addr={.s_addr=htonl(0xe00000fb)}};
  memset(&control,0,sizeof control);io.iov_base=negative_packet;io.iov_len=negative_length;
  msg=(struct msghdr){.msg_name=&dest,.msg_namelen=sizeof dest,.msg_iov=&io,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=CMSG_SPACE(sizeof(struct in_pktinfo))};
  struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c->cmsg_level=IPPROTO_IP;c->cmsg_type=IP_PKTINFO;c->cmsg_len=CMSG_LEN(sizeof(struct in_pktinfo));
  struct in_pktinfo *info=(struct in_pktinfo *)CMSG_DATA(c);info->ipi_ifindex=iface;info->ipi_spec_dst=negative_source;
  if(sendmsg(fd,&msg,MSG_DONTWAIT)==(ssize_t)negative_length)negative_last=seconds;
 }
}
static int negative_start(const char *source) {
 negative_length=mdns_nsec(negative_packet,hostname);
 if(!negative_length||inet_pton(AF_INET,source,&negative_source)!=1)return -1;
 int fd=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);if(fd<0)return -1;
 int one=1,ttl=255,zero=0;
 // Bind only the multicast destination: never steal Avahi's unicast QU replies.
 struct sockaddr_in local={.sin_family=AF_INET,.sin_port=htons(5353),.sin_addr={.s_addr=htonl(0xe00000fb)}};
 struct ip_mreqn membership={.imr_multiaddr=local.sin_addr,.imr_address=negative_source,.imr_ifindex=iface};
 if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one)||
    setsockopt(fd,IPPROTO_IP,IP_PKTINFO,&one,sizeof one)||setsockopt(fd,IPPROTO_IP,IP_RECVTTL,&one,sizeof one)||
    setsockopt(fd,IPPROTO_IP,IP_MULTICAST_TTL,&ttl,sizeof ttl)||setsockopt(fd,IPPROTO_IP,IP_MULTICAST_LOOP,&zero,sizeof zero)||
    bind(fd,(struct sockaddr *)&local,sizeof local)||setsockopt(fd,IPPROTO_IP,IP_ADD_MEMBERSHIP,&membership,sizeof membership)) {close(fd);return -1;}
 negative_watch=avahi_simple_poll_get(poller)->watch_new(avahi_simple_poll_get(poller),fd,AVAHI_WATCH_IN,negative_read,NULL);
 if(!negative_watch){close(fd);return -1;}negative_fd=fd;return 0;
}
static void negative_stop(void) {
 if(negative_watch)avahi_simple_poll_get(poller)->watch_free(negative_watch);
 if(negative_fd>=0)close(negative_fd);
}
