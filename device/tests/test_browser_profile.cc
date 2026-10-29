#include "profile_model.h"
#include "profile_client.h"
#include "cJSON.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
int main(int argc,char**argv){
 assert(argc>=2);std::ifstream f(argv[1]);std::string json((std::istreambuf_iterator<char>(f)),{});
 if(argc==3&&!strcmp(argv[2],"text-reject")){assert(!meshpn_profile_json_text_safe(json.data(),json.size()));return 0;}
 assert(meshpn_profile_json_text_safe(json.data(),json.size()));
 cJSON*j=cJSON_Parse(json.c_str());assert(j);meshpn_tls_profile_t p{};
 if(argc==3&&!strcmp(argv[2],"reject")){assert(!meshpn_profile_parse(j,&p));cJSON_Delete(j);return 0;}
 assert(meshpn_profile_parse(j,&p));cJSON_Delete(j);meshvpn_profile_check_t check{};
 bool ok=meshpn_profile_preview(&p,&check);
 if(argc==3&&!strcmp(argv[2],"mismatch")){assert(!ok);return 0;}
 if(!ok)fprintf(stderr,"preview mismatch: %s %s, expected %s %s\n",check.ja3,check.ja4,p.ja3,p.ja4);
 assert(ok);
 // Independent observer consumes the freshly generated wire, never expected JSON.
 bssl::UniquePtr<SSL_CTX>ctx(meshvpn_profiled_context(true,&p));assert(ctx);
 bssl::UniquePtr<SSL>ssl(SSL_new(ctx.get()));assert(ssl);assert(meshvpn_profiled_connection(ssl.get(),&p));
 assert(SSL_set_tlsext_host_name(ssl.get(),"exit.meshpn.test"));
 BIO*in=BIO_new(BIO_s_mem()),*out=BIO_new(BIO_s_mem());assert(in&&out);SSL_set_bio(ssl.get(),in,out);SSL_set_connect_state(ssl.get());
 meshvpn_profile_gate_state gate;meshvpn_profiled_gate_install(ssl.get(),&gate,&p);SSL_do_handshake(ssl.get());assert(gate.accepted);
 char*wire=nullptr;long size=BIO_get_mem_data(out,&wire);assert(size>0);assert(fwrite(wire,1,size,stdout)==(size_t)size);
}
