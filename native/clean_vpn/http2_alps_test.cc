#include "http2_alps.hpp"
#include <cstring>
#include <iostream>
#include <memory>
using namespace cvpn::http2_alps;
using Session=std::unique_ptr<nghttp2_session,decltype(&nghttp2_session_del)>;
Session session(bool server) {
  nghttp2_session_callbacks* cb=nullptr;require(nghttp2_session_callbacks_new(&cb)==0);
  nghttp2_session* s=nullptr;
  int rc=server?nghttp2_session_server_new(&s,cb,nullptr):nghttp2_session_client_new(&s,cb,nullptr);
  nghttp2_session_callbacks_del(cb);require(rc==0);return Session(s,nghttp2_session_del);
}
std::vector<uint8_t> send(nghttp2_session* s) {
  std::vector<uint8_t> out;const uint8_t* p=nullptr;ssize_t n;
  while((n=nghttp2_session_mem_send(s,&p))>0)out.insert(out.end(),p,p+n);
  require(n==0);return out;
}
void receive(nghttp2_session* s,const std::vector<uint8_t>& bytes) {
  // Fragmentation must not disable or bypass real preface parsing.
  for(auto b:bytes)require(nghttp2_session_mem_recv(s,&b,1)==1);
}
template<class F> void rejects(F f) {bool rejected=false;try{f();}catch(const std::exception&){rejected=true;}require(rejected);}
int main() {
  try {
    auto settings=server_settings();auto encoded=encode(settings);auto decoded=parse(encoded.data(),encoded.size());
    require(decoded.size()==3 && decoded[1].value==1048576);
    require(parse(nullptr,0).empty());
    for(size_t n=1;n<encoded.size();n++)rejects([&]{parse(encoded.data(),n);});
    for(size_t offset:{size_t(0),size_t(1),size_t(2),size_t(3),size_t(4),size_t(5),size_t(6),size_t(7),size_t(8)}) {
      auto b=encoded;b[offset]^=0x80;rejects([&]{parse(b.data(),b.size());});
    }
    for(auto invalid:std::vector<std::vector<nghttp2_settings_entry>>{
      {{1,65537}},{{2,1}},{{4,0x80000000}},{{5,16383}},{{5,16777216}},{{8,1}},{{3,1},{3,2}}}) {
      auto b=encode(invalid);rejects([&]{parse(b.data(),b.size());});
    }
    auto extra=encoded;extra.insert(extra.end(),encoded.begin(),encoded.end());rejects([&]{parse(extra.data(),extra.size());});
    auto client=session(false),server=session(true);
    require(cvpn_h2_remote_alps(client.get(),settings.data(),settings.size())==0);
    require(cvpn_h2_remote_alps(client.get(),settings.data(),settings.size())<0);
    require(cvpn_h2_local_alps(server.get(),settings.data(),settings.size())==0);
    require(nghttp2_session_get_remote_settings(client.get(),NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE)==1048576);
    require(nghttp2_session_get_local_settings(server.get(),NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE)==1048576);
    // No SETTINGS or synthetic ACK from either side due to ALPS alone.
    auto magic=send(client.get());require(magic.size()==NGHTTP2_CLIENT_MAGIC_LEN);
    require(std::memcmp(magic.data(),NGHTTP2_CLIENT_MAGIC,magic.size())==0);
    require(send(server.get()).empty());
    auto client_settings=settings;client_settings.push_back({NGHTTP2_SETTINGS_ENABLE_PUSH,0});
    require(nghttp2_submit_settings(client.get(),0,client_settings.data(),client_settings.size())==0);
    auto wire=send(client.get());require(wire==encode(client_settings));
    receive(server.get(),magic);receive(server.get(),wire);
    auto ack=send(server.get());require(ack==std::vector<uint8_t>({0,0,0,4,1,0,0,0,0}));
    receive(client.get(),ack);require(send(client.get()).empty());
    // ALPS did not consume stream 1, and normal subsequent SETTINGS still ACK.
    nghttp2_nv headers[]={
      {reinterpret_cast<uint8_t*>(const_cast<char*>(":method")),reinterpret_cast<uint8_t*>(const_cast<char*>("GET")),7,3,0},
      {reinterpret_cast<uint8_t*>(const_cast<char*>(":scheme")),reinterpret_cast<uint8_t*>(const_cast<char*>("https")),7,5,0},
      {reinterpret_cast<uint8_t*>(const_cast<char*>(":path")),reinterpret_cast<uint8_t*>(const_cast<char*>("/")),5,1,0},
      {reinterpret_cast<uint8_t*>(const_cast<char*>(":authority")),reinterpret_cast<uint8_t*>(const_cast<char*>("localhost")),10,9,0}};
    require(nghttp2_submit_request(client.get(),nullptr,headers,4,nullptr,nullptr)==1);
    receive(server.get(),send(client.get()));
    nghttp2_settings_entry update{NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,65535};
    require(nghttp2_submit_settings(server.get(),0,&update,1)==0);
    receive(client.get(),send(server.get()));ack=send(client.get());require(ack==std::vector<uint8_t>({0,0,0,4,1,0,0,0,0}));
    receive(server.get(),ack);
    require(nghttp2_session_get_remote_settings(client.get(),NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE)==65535);
    auto bad=session(true);require(cvpn_h2_local_alps(bad.get(),settings.data(),settings.size())==0);
    magic[0]='X';require(nghttp2_session_mem_recv(bad.get(),magic.data(),magic.size())==NGHTTP2_ERR_BAD_CLIENT_MAGIC);
    std::cout<<"ALPS parser, no-ACK settings, stream 1, real preface and later SETTINGS PASS\n";
  }catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;}
}
