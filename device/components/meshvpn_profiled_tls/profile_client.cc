#include "profile_client.h"
#include "cert_decode.h"
#include <cstring>
static bool has(const meshpn_profile_ids_t &a,uint16_t n){for(unsigned i=0;i<a.count;i++)if(a.values[i]==n)return true;return false;}
SSL_CTX *meshvpn_profiled_context(bool configured,const meshpn_tls_profile_t *profile) {
 const auto &p=profile?*profile:meshpn_builtin_profile;
 SSL_CTX *ctx=SSL_CTX_new(TLS_client_method()); if(!ctx)return nullptr;
 SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,nullptr);
 SSL_CTX_set_min_proto_version(ctx,TLS1_2_VERSION);SSL_CTX_set_max_proto_version(ctx,TLS1_3_VERSION);
 static const uint8_t alpn[]={2,'h','2',8,'h','t','t','p','/','1','.','1'};
 if(SSL_CTX_set_alpn_protos(ctx,alpn,p.http1?sizeof(alpn):3))goto fail;
 if(configured){
  SSL_CTX_set_permute_extensions(ctx,0);SSL_CTX_set_grease_enabled(ctx,p.grease);
  if(has(p.extensions,5))SSL_CTX_enable_ocsp_stapling(ctx);
  if(has(p.extensions,18))SSL_CTX_enable_signed_cert_timestamps(ctx);
  if(has(p.extensions,51764)&&!SSL_CTX_set1_requested_trust_anchors(ctx,nullptr,0))goto fail;
  if(has(p.extensions,27)&&!SSL_CTX_add_cert_compression_alg(ctx,2,nullptr,meshpn_cert::decode))goto fail;
  uint16_t suites[32];size_t count=0;char legacy[2048]={};
  for(unsigned i=0;i<p.ciphers.count;i++){
   auto id=p.ciphers.values[i];if(id>=0x1301&&id<=0x1303){suites[count++]=id;continue;}
   const SSL_CIPHER*cipher=SSL_get_cipher_by_value(id);if(!cipher)goto fail;
   const char*name=SSL_CIPHER_get_name(cipher);size_t used=strlen(legacy),n=strlen(name);
   if(used+n+2>sizeof(legacy))goto fail;
   if(used)strcat(legacy,":");
   strcat(legacy,name);
  }
  if(!count||!SSL_CTX_set_tls13_client_cipher_order(ctx,suites,count)||
    !SSL_CTX_set1_group_ids(ctx,p.groups.values,p.groups.count)||
    !SSL_CTX_set_cipher_list(ctx,legacy)||
    !SSL_CTX_set_verify_algorithm_prefs(ctx,p.signatures.values,p.signatures.count)||
    !SSL_CTX_set_meshvpn_signature_algorithms_clienthello_wire(ctx,p.signatures.values,p.signatures.count))goto fail;
 }
 return ctx;
fail:SSL_CTX_free(ctx);return nullptr;
}
bool meshvpn_profiled_connection(SSL*ssl,const meshpn_tls_profile_t*profile){
 const auto&p=profile?*profile:meshpn_builtin_profile;
 SSL_set_enable_ech_grease(ssl,has(p.extensions,65037));SSL_set_alps_use_new_codepoint(ssl,1);
 return SSL_set_meshpn_extension_order(ssl,p.extensions.values,p.extensions.count)&&
 SSL_set1_client_key_shares(ssl,p.shares.values,p.shares.count)&&
 (!has(p.extensions,17613)||SSL_add_application_settings(ssl,reinterpret_cast<const uint8_t*>("h2"),2,nullptr,0));
}

static void observe_hello(int writing,int,int type,const void*data,size_t length,
                          SSL*,void*arg){
 auto* state=static_cast<meshvpn_profile_gate_state*>(arg);
 if(!writing||type!=SSL3_RT_HANDSHAKE||!length||static_cast<const uint8_t*>(data)[0]!=SSL3_MT_CLIENT_HELLO)return;
 ++state->hellos;
 state->accepted=meshvpn_profiled_tls_check_expected(static_cast<const uint8_t*>(data),length,state->profile->ja3,state->profile->ja4,&state->check);
}
void meshvpn_profiled_gate_install(SSL*ssl,meshvpn_profile_gate_state*state,const meshpn_tls_profile_t*profile){
 *state={}; state->profile=profile?profile:&meshpn_builtin_profile;
 SSL_set_msg_callback(ssl,observe_hello);
 SSL_set_msg_callback_arg(ssl,state);
}

#include <sys/socket.h>
#include <cerrno>
static int gate_create(BIO*b){BIO_set_init(b,1);return 1;}
static int gate_destroy(BIO*b){BIO_set_data(b,nullptr);BIO_set_init(b,0);return 1;}
static int gate_read(BIO*b,char*data,int length){
 auto*g=static_cast<meshvpn_profile_gate_state*>(BIO_get_data(b));
 BIO_clear_retry_flags(b);
 int n=recv(g->fd,data,length,0);
 if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))BIO_set_retry_read(b);
 return n;
}
static int gate_write(BIO*b,const char*data,int length){
 auto*g=static_cast<meshvpn_profile_gate_state*>(BIO_get_data(b));
 BIO_clear_retry_flags(b);
 if(!g->accepted||!g->hellos){errno=EPROTO;return -1;}
 int n=send(g->fd,data,length,0);
 if(n>0)g->sent_bytes+=n;
 if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))BIO_set_retry_write(b);
 return n;
}
static long gate_ctrl(BIO*,int command,long,void*){return command==BIO_CTRL_FLUSH?1:0;}
static BIO_METHOD* gate_method(){
 auto*m=BIO_meth_new(BIO_TYPE_SOURCE_SINK,"meshpn profile gate");
 if(!m)return nullptr;
 if(!BIO_meth_set_create(m,gate_create)||!BIO_meth_set_destroy(m,gate_destroy)||!BIO_meth_set_read(m,gate_read)||!BIO_meth_set_write(m,gate_write)||!BIO_meth_set_ctrl(m,gate_ctrl)){BIO_meth_free(m);return nullptr;}
 return m;
}
bool meshvpn_profiled_attach_fd(SSL*ssl,int fd,meshvpn_profile_gate_state*state,const meshpn_tls_profile_t*profile){
 // Method is immutable; the accepted flag/capture belongs to each connection.
 static bssl::UniquePtr<BIO_METHOD> method(gate_method());
 if(!ssl||!state||fd<0||!method)return false;
 BIO*b=BIO_new(method.get());if(!b)return false;
 meshvpn_profiled_gate_install(ssl,state,profile);state->fd=fd;
 BIO_set_data(b,state);SSL_set_bio(ssl,b,b);return true;
}

extern "C" bool meshpn_profile_preview(const meshpn_tls_profile_t*p,meshvpn_profile_check_t*out){
 if(!p||!out)return false;
 *out={};
 bssl::UniquePtr<SSL_CTX>ctx(meshvpn_profiled_context(true,p));if(!ctx)return false;
 bssl::UniquePtr<SSL>ssl(SSL_new(ctx.get()));if(!ssl||!meshvpn_profiled_connection(ssl.get(),p)||!SSL_set_tlsext_host_name(ssl.get(),"exit.meshpn.test"))return false;
 BIO *in=BIO_new(BIO_s_mem()),*write=BIO_new(BIO_s_mem());
 if(!in||!write){BIO_free(in);BIO_free(write);return false;}
 SSL_set_bio(ssl.get(),in,write);SSL_set_connect_state(ssl.get());
 meshvpn_profile_gate_state gate;meshvpn_profiled_gate_install(ssl.get(),&gate,p);
 (void)SSL_do_handshake(ssl.get());*out=gate.check;return gate.hellos==1&&gate.accepted;
}
