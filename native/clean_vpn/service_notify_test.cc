#include "service_notify.hpp"
#include <iostream>
#include <poll.h>
static void need(bool ok){if(!ok)throw std::runtime_error("notify_test");}
int main(){
  try{
    unsetenv("NOTIFY_SOCKET");cvpn::ServiceNotify none(true);need(none.state("ready"));
    setenv("NOTIFY_SOCKET","invalid",1);
    bool rejected=false;try{cvpn::ServiceNotify bad(true);}catch(...){rejected=true;}need(rejected);
    for(bool abstract:{false,true}){
      std::string path=(abstract?"@cvpn-notify-":"/tmp/cvpn-notify-")+std::to_string(getpid());
      sockaddr_un address{};address.sun_family=AF_UNIX;memcpy(address.sun_path,path.c_str(),path.size()+1);
      auto length=offsetof(sockaddr_un,sun_path)+path.size()+1;
      if(abstract){address.sun_path[0]=0;--length;}
      int fd=socket(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0);need(fd>=0);
      need(bind(fd,reinterpret_cast<sockaddr*>(&address),length)==0);
      setenv("NOTIFY_SOCKET",path.c_str(),1);
      cvpn::ServiceNotify notify(true);
      const std::string states[]={"connecting","ready","ready","stopped"};
      const std::string expected[]={"STATUS=connecting","STATUS=ready\nREADY=1","STATUS=ready","STATUS=stopped\nSTOPPING=1"};
      for(int i=0;i<4;i++){
        need(notify.state(states[i]));pollfd p{fd,POLLIN,0};need(poll(&p,1,100)==1);
        char b[256];auto n=recv(fd,b,sizeof(b),0);need(n>0&&std::string(b,n)==expected[i]);
      }
      need(!notify.state("ready\nMAINPID=1"));
      pollfd p{fd,POLLIN,0};need(poll(&p,1,0)==0);
      close(fd);if(!abstract)unlink(path.c_str());
    }
    std::cout<<"native notify filesystem/abstract, readiness once, bounded metadata PASS\n";
  }catch(...){return 1;}
}
