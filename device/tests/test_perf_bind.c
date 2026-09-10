#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#define MESHPN_BIND_TEST 1
#ifndef IP_BOUND_IF
#define IP_BOUND_IF 25
#endif
static int closes, sets, fail_set, fail_get, wrong_index;
static unsigned expected_index=13;
static const char *interface="en13";
static int test_socket(int domain,int type,int protocol)
{ (void)domain;(void)type;(void)protocol;return 7; }
static char *test_getenv(const char *key) { (void)key;return (char *)interface; }
static unsigned test_index(const char *name) { (void)name;return expected_index; }
static int test_close(int fd) { assert(fd==7);closes++;return 0; }
static int test_set(int fd,int level,int option,const void *value,socklen_t len)
{
    assert(fd==7&&level==IPPROTO_IP&&option==IP_BOUND_IF&&len==sizeof(unsigned));
    assert(*(const unsigned *)value==expected_index);sets++;errno=ENOTSUP;return fail_set?-1:0;
}
static int test_get(int fd,int level,int option,void *value,socklen_t *len)
{
    assert(fd==7&&level==IPPROTO_IP&&option==IP_BOUND_IF&&*len==sizeof(unsigned));
    *(unsigned *)value=wrong_index?99:expected_index;errno=ENOTSUP;return fail_get?-1:0;
}
#define socket test_socket
#define getenv test_getenv
#define if_nametoindex test_index
#define close test_close
#define setsockopt test_set
#define getsockopt test_get
#include "../scripts/perf-bind-darwin.c"
int main(void)
{
    assert(meshpn_socket(AF_INET,SOCK_STREAM,0)==7&&sets==1);
    interface="en0";expected_index=4;
    assert(meshpn_socket(AF_INET,SOCK_DGRAM,0)==7&&sets==2);
    fail_set=1;assert(meshpn_socket(AF_INET,SOCK_STREAM,0)==-1&&closes==1&&errno==ENOTSUP);
    fail_set=0;fail_get=1;assert(meshpn_socket(AF_INET,SOCK_STREAM,0)==-1&&closes==2);
    fail_get=0;wrong_index=1;assert(meshpn_socket(AF_INET,SOCK_STREAM,0)==-1&&closes==3);
    wrong_index=0;expected_index=0;assert(meshpn_socket(AF_INET,SOCK_STREAM,0)==-1&&closes==4&&errno==ENXIO);
    assert(meshpn_socket(AF_INET6,SOCK_STREAM,0)==-1&&errno==EAFNOSUPPORT);
    assert(meshpn_socket(AF_UNIX,SOCK_STREAM,0)==7);
    interface=NULL;assert(meshpn_socket(AF_INET,SOCK_STREAM,0)==-1&&errno==EINVAL);
    puts("Native interface socket binding and fail-closed tests passed");
}
