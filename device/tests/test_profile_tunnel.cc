// Exercise exactly the production TLS session against the real JS exit.
#include "profile_tunnel.h"
extern "C" {
#include "meshvpn_vpn_frame.h"
}
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <chrono>
#include <string>
#include <fstream>
#include <iterator>
struct Test {
    uint8_t frame[1404]{};
    size_t frame_length=144;
    meshvpn_vpn_decoder_t rx{};
    unsigned sent=0,received=0,ready=0,peeks=0;
    size_t offset=0;
    bool failed=false,cancel_ready=false;
    unsigned total=64;
    meshvpn_profile_tunnel_diag_t diag{};
    std::chrono::steady_clock::time_point end=std::chrono::steady_clock::now()+std::chrono::seconds(14);
};
static bool current(void *p) { auto &t=*static_cast<Test*>(p);return !(t.cancel_ready&&t.ready)&&!t.failed&&t.received<t.total&&std::chrono::steady_clock::now()<t.end; }
static void diagnostic(void *p,const meshvpn_profile_tunnel_diag_t*d) { static_cast<Test*>(p)->diag=*d; }
static void ready(void *p) { static_cast<Test*>(p)->ready++; }
static size_t peek(void *p,const uint8_t **out) {
    auto&t=*static_cast<Test*>(p);assert(t.ready==1);t.peeks++;
    if(t.sent>=t.total)return 0;
    *out=t.frame+t.offset;return t.frame_length-t.offset;
}
static void sent(void *p,size_t n) { auto&t=*static_cast<Test*>(p);t.offset+=n;assert(t.offset<=t.frame_length);if(t.offset==t.frame_length){t.sent++;t.offset=0;} }
static bool packet(void*p,const uint8_t*b,size_t n) { auto&t=*static_cast<Test*>(p);if(n!=t.frame_length-4||memcmp(b,t.frame+4,n)){t.failed=true;return false;}t.received++;return true; }
static bool receive(void*p,const uint8_t*b,size_t n) { auto&t=*static_cast<Test*>(p);return meshvpn_vpn_decode(&t.rx,b,n,packet,p); }
static bool healthy(void*p) { return !static_cast<Test*>(p)->failed; }
static std::string readfile(const char *p) {std::ifstream f(p);return std::string(std::istreambuf_iterator<char>(f),{});}
int run_once(int argc,char**argv) {
    signal(SIGPIPE,SIG_IGN);
    if(argc!=6)return 2;
    Test test;std::string mode=argv[5];test.cancel_ready=mode=="cancel";
    if(mode=="disconnect"||mode=="invalid"||mode=="backpressure")test.total=10000000;
    if(mode=="bulk") {test.frame_length=1404;test.total=1024;}
    size_t packet_length=test.frame_length-4;
    meshvpn_vpn_frame_header(test.frame,packet_length);
    auto*p=test.frame+4;p[0]=0x45;p[2]=packet_length>>8;p[3]=packet_length;p[8]=64;p[9]=17;
    p[12]=10;p[13]=99;p[15]=2;p[16]=1;p[17]=1;p[18]=1;p[19]=1;p[24]=(packet_length-20)>>8;p[25]=packet_length-20;
    assert(meshvpn_vpn_repair_checksums(p,packet_length));
    int fd=socket(AF_INET,SOCK_STREAM,0);assert(fd>=0);
    sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);addr.sin_port=htons(atoi(argv[1]));
    assert(connect(fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))==0);
    assert(fcntl(fd,F_SETFL,fcntl(fd,F_GETFL,0)|O_NONBLOCK)==0);
    std::string ca=readfile(argv[2]),key=readfile(argv[3]);
    meshvpn_profile_tunnel_options_t o{fd,argv[4],ca.c_str(),key.c_str(),mode=="profile"?"unsupported":MESHPN_TLS_PROFILE_ID,
        &test,current,diagnostic,ready,peek,sent,receive,healthy};
    if(mode=="cancel_auth"||mode=="cancel_handshake")test.end=std::chrono::steady_clock::now()+std::chrono::milliseconds(100);
    int rc=meshvpn_profile_tunnel_run(&o);close(fd);
    printf("{\"rc\":%d,\"ready\":%u,\"packets\":%u,\"sent\":%u,\"peeks\":%u,\"phase\":\"%s\",\"alpn\":\"%s\",\"ja3\":\"%s\",\"ja4\":\"%s\",\"hellos\":%u,\"tls_bytes\":%llu}\n",rc,test.ready,test.received,test.sent,test.peeks,test.diag.phase,test.diag.alpn,test.diag.actual.ja3,test.diag.actual.ja4,test.diag.hellos,static_cast<unsigned long long>(test.diag.tls_bytes_sent));
    if(mode=="success"||mode=="bulk")return !(rc==ECANCELED&&test.received==test.total&&test.ready==1&&test.diag.actual.match);
    if(mode=="cancel")return !(rc==ECANCELED&&test.ready==1&&test.peeks==0);
    if(mode=="disconnect"||mode=="invalid"||mode=="backpressure")return !(rc!=0&&test.ready==1&&test.received<test.total);
    return !(rc!=0&&test.ready==0&&test.peeks==0);
}

extern "C" size_t meshpn_test_heap_live();
extern "C" void meshpn_test_heap_report();
int main(int argc,char**argv) {
    if(argc!=6)return 2;
    atexit(meshpn_test_heap_report);
    if(strcmp(argv[5],"repeat"))return run_once(argc,argv);
    char success[]="success";argv[5]=success;size_t baseline=0;
    for(unsigned i=0;i<20;i++) {
        int rc=run_once(argc,argv);if(rc)return rc;
        if(!i)baseline=meshpn_test_heap_live();
        else assert(meshpn_test_heap_live()==baseline); // one immutable BIO method may persist
    }
    return 0;
}
