// Application traffic for the isolated real-TUN lab. No Node packet fixture.
#include <arpa/inet.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <chrono>
#include <algorithm>
static void require(bool b,const char* e){if(!b)throw std::runtime_error(e);}
static const char* origin_ip="1.1.1.1";
static sockaddr_in addr(int port){sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(port);require(inet_pton(AF_INET,origin_ip,&a.sin_addr)==1,"address");return a;}
static int sock(int type){int s=socket(AF_INET,type,0);require(s>=0,"socket");timeval t{5,0};setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&t,sizeof(t));setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,&t,sizeof(t));return s;}
static void send_all(int s,const char* p,size_t n){while(n){ssize_t k=send(s,p,n,0);require(k>0,"send");p+=k;n-=k;}}
static void receive_all(int s,char* p,size_t n){while(n){ssize_t k=recv(s,p,n,0);require(k>0,"receive");p+=k;n-=k;}}
int main(int argc,char** argv){
  signal(SIGPIPE,SIG_IGN);
  try{
    require(argc>=2&&argc<=4,"usage");const std::string mode=argv[1];bool server=mode=="serve";
    if(mode=="ipv6-serve"||mode=="ipv6-probe"){
      int fd=socket(AF_INET6,SOCK_DGRAM,0);require(fd>=0,"ipv6_socket");timeval timeout{3,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
      sockaddr_in6 a{};a.sin6_family=AF_INET6;a.sin6_port=htons(53535);require(inet_pton(AF_INET6,"2001:db8:1::216",&a.sin6_addr)==1,"ipv6_address");
      if(mode=="ipv6-serve"){
        require(bind(fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0,"ipv6_bind");
        for(;;){char b[32];sockaddr_in6 peer{};socklen_t size=sizeof(peer);ssize_t n=recvfrom(fd,b,sizeof(b),0,reinterpret_cast<sockaddr*>(&peer),&size);if(n>0)sendto(fd,b,n,0,reinterpret_cast<sockaddr*>(&peer),size);}
      }
      require(connect(fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0,"ipv6_connect");const char payload[]="native-ipv6-guard-probe";char reply[sizeof(payload)];
      require(send(fd,payload,sizeof(payload),0)==sizeof(payload)&&recv(fd,reply,sizeof(reply),0)==sizeof(reply)&&memcmp(payload,reply,sizeof(reply))==0,"ipv6_echo");close(fd);std::cout<<"IPv6 positive control PASS\n";return 0;
    }
    if(server){
      if(argc==3)origin_ip=argv[2];
      int udp=sock(SOCK_DGRAM),dns=sock(SOCK_DGRAM),tcp=sock(SOCK_STREAM),dns_tcp=sock(SOCK_STREAM);int one=1;setsockopt(tcp,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));setsockopt(dns_tcp,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
      auto u=addr(53535),d=addr(53),t=addr(4444);
      require(bind(udp,reinterpret_cast<sockaddr*>(&u),sizeof(u))==0&&bind(dns,reinterpret_cast<sockaddr*>(&d),sizeof(d))==0&&bind(tcp,reinterpret_cast<sockaddr*>(&t),sizeof(t))==0&&listen(tcp,1)==0&&bind(dns_tcp,reinterpret_cast<sockaddr*>(&d),sizeof(d))==0&&listen(dns_tcp,4)==0,"bind");
      std::cout<<"origin ready\n"<<std::flush;
      while(true){
        pollfd f[]={{udp,POLLIN,0},{dns,POLLIN,0},{tcp,POLLIN,0},{dns_tcp,POLLIN,0}};require(poll(f,4,10000)>=0,"poll");
        for(int i=0;i<2;i++)if(f[i].revents&POLLIN){
          char b[65536];sockaddr_in peer{};socklen_t len=sizeof(peer);ssize_t n=recvfrom(f[i].fd,b,sizeof(b),0,reinterpret_cast<sockaddr*>(&peer),&len);require(n>0,"udp_receive");
          if(i==1){require(n>=12,"dns_header");b[2]=char(0x81);b[3]=char(0x83);}
          require(sendto(f[i].fd,b,n,0,reinterpret_cast<sockaddr*>(&peer),len)==n,"udp_send");
        }
        if(f[2].revents&POLLIN){int s=accept(tcp,nullptr,nullptr);require(s>=0,"accept");char b[16384];ssize_t n;while((n=recv(s,b,sizeof(b),0))>0)send_all(s,b,n);close(s);}
        if(f[3].revents&POLLIN){int s=accept(dns_tcp,nullptr,nullptr);require(s>=0,"accept");unsigned char prefix[2];receive_all(s,reinterpret_cast<char*>(prefix),2);size_t n=(size_t(prefix[0])<<8)|prefix[1];require(n>=12,"dns_length");std::vector<char>b(n);receive_all(s,b.data(),n);b[2]=char(0x81);b[3]=char(0x83);send_all(s,reinterpret_cast<char*>(prefix),2);send_all(s,b.data(),n);close(s);}
      }
    }
    require(mode=="probe"||mode=="data"||mode=="dns"||mode=="bench","mode");
    if(mode=="data"&&argc==3)origin_ip=argv[2];
    if(mode=="probe"||mode=="data"){
    int udp=sock(SOCK_DGRAM);auto u=addr(53535);
    int fragment=IP_PMTUDISC_DONT;require(setsockopt(udp,IPPROTO_IP,IP_MTU_DISCOVER,&fragment,sizeof(fragment))==0,"fragment_mode");
    require(connect(udp,reinterpret_cast<sockaddr*>(&u),sizeof(u))==0,"udp_connect");
    for(size_t size:{28,1300,2000,8192,60000}){
      std::vector<char> b(size),reply(size+1);for(size_t i=0;i<size;i++)b[i]=char(i%251);
      require(send(udp,b.data(),b.size(),0)==ssize_t(size),"udp_send");ssize_t n=recv(udp,reply.data(),reply.size(),0);require(n==ssize_t(size)&&memcmp(b.data(),reply.data(),size)==0,"udp_bytes");
      std::cout<<"UDP "<<size<<" PASS\n";
    }
    close(udp);
    }
    if(mode=="probe"||mode=="dns")for(bool stream:{false,true}){
    int dns=sock(stream?SOCK_STREAM:SOCK_DGRAM);auto d=addr(53);
    if(argc>=3)require(inet_pton(AF_INET,argv[2],&d.sin_addr)==1,"dns_target");
    if(argc==4)d.sin_port=htons(std::stoi(argv[3]));
    require(connect(dns,reinterpret_cast<sockaddr*>(&d),sizeof(d))==0,"dns_connect");
    const unsigned char query[]={0x12,0x34,1,0,0,1,0,0,0,0,0,0,4,'t','e','s','t',7,'i','n','v','a','l','i','d',0,0,1,0,1};
    if(stream){char prefix[]={0,char(sizeof(query))};send_all(dns,prefix,2);}
    require(send(dns,query,sizeof(query),0)==sizeof(query),"dns_send");unsigned char answer[128];ssize_t n;
    if(stream){unsigned char prefix[2];receive_all(dns,reinterpret_cast<char*>(prefix),2);n=(unsigned(prefix[0])<<8)|prefix[1];require(n<=128,"dns_length");receive_all(dns,reinterpret_cast<char*>(answer),n);}else n=recv(dns,answer,sizeof(answer),0);
    require(n==sizeof(query)&&answer[0]==0x12&&answer[1]==0x34&&answer[2]==0x81&&answer[3]==0x83&&memcmp(answer+4,query+4,sizeof(query)-4)==0,"dns_answer");close(dns);std::cout<<"DNS "<<(stream?"TCP":"UDP")<<" PASS\n";
    }
    if(mode=="dns")return 0;
    auto start=std::chrono::steady_clock::now();
    int tcp=sock(SOCK_STREAM);auto t=addr(4444);require(connect(tcp,reinterpret_cast<sockaddr*>(&t),sizeof(t))==0,"tcp_connect");
    std::vector<char> b(65536),reply(b.size());for(size_t i=0;i<b.size();i++)b[i]=char(i%251);
    if(mode=="bench"){
      std::vector<double> samples;
      for(int i=0;i<100;i++){
        auto at=std::chrono::steady_clock::now();send_all(tcp,b.data(),32);receive_all(tcp,reply.data(),32);require(memcmp(b.data(),reply.data(),32)==0,"latency_bytes");
        samples.push_back(std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-at).count());
      }
      std::sort(samples.begin(),samples.end());std::cout<<"LATENCY median_ms="<<samples[49]<<" p95_ms="<<samples[94]<<"\n";start=std::chrono::steady_clock::now();
    }
    const int loops=mode=="bench"?256:16;
    for(int i=0;i<loops;i++){send_all(tcp,b.data(),b.size());receive_all(tcp,reply.data(),reply.size());require(b==reply,"tcp_bytes");}
    close(tcp);const double seconds=std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();
    std::cout<<"TCP "<<loops*65536<<" bytes roundtrip PASS seconds="<<seconds<<"\nNATIVE_TUN_PROBE_PASS\n";return 0;
  }catch(const std::exception& e){std::cerr<<"probe failed: "<<e.what()<<" errno="<<errno<<"\n";return 1;}
}
