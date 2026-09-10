/* Native macOS smoke test: no network traffic, only socket options. */
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
int main(void)
{
    unsigned expected=if_nametoindex(getenv("MESHPN_IPERF_IFACE"));
    if (!expected) return 2;
    const int types[]={SOCK_STREAM,SOCK_DGRAM};
    for (unsigned i=0;i<2;i++) {
        int fd=socket(AF_INET,types[i],0);
        unsigned actual=0; socklen_t len=sizeof(actual);
        if (fd<0) return 3;
        int rc=getsockopt(fd,IPPROTO_IP,IP_BOUND_IF,&actual,&len);
        close(fd);
        if (rc<0 || len!=sizeof(actual) || actual!=expected) return 4;
    }
    puts("TCP/UDP native binding verified");
    return 0;
}
