#pragma once
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <cstddef>
#include <stdexcept>
#include <string>

namespace cvpn {
// Metadata only; no libsystemd dependency, descriptors or payload transfer.
// https://github.com/systemd/systemd/blob/main/man/sd_notify.xml
class ServiceNotify {
  int fd_=-1;
  bool ready_=false;
public:
  explicit ServiceNotify(bool enabled) {
    if(!enabled)return;
    const char* path=std::getenv("NOTIFY_SOCKET");
    if(!path)return; // foreground service mode is also useful without systemd
    sockaddr_un address{};address.sun_family=AF_UNIX;
    size_t n=std::strlen(path);
    if(n<2||n>=sizeof(address.sun_path)||(path[0]!='/'&&path[0]!='@'))
      throw std::runtime_error("notify_path");
    std::memcpy(address.sun_path,path,n+1);
    socklen_t length=offsetof(sockaddr_un,sun_path)+n+1;
    if(path[0]=='@'){address.sun_path[0]=0;--length;}
    fd_=socket(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
    if(fd_<0)throw std::runtime_error("notify_socket");
    if(connect(fd_,reinterpret_cast<sockaddr*>(&address),length)!=0){
      close(fd_);fd_=-1;throw std::runtime_error("notify_connect");
    }
  }
  ~ServiceNotify(){if(fd_>=0)close(fd_);}
  ServiceNotify(const ServiceNotify&)=delete;
  ServiceNotify& operator=(const ServiceNotify&)=delete;
  bool state(const std::string& state) {
    if(fd_<0)return true;
    // Fixed engine vocabulary only, even if a future caller passes bad input.
    if(state.empty()||state.size()>64||state.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789_")!=std::string::npos)return false;
    std::string message="STATUS="+state;
    if(!ready_&&(state=="ready"||state=="listening")){message+="\nREADY=1";ready_=true;}
    if(state=="stopped")message+="\nSTOPPING=1";
    return send(fd_,message.data(),message.size(),MSG_NOSIGNAL)==ssize_t(message.size());
  }
};
}
