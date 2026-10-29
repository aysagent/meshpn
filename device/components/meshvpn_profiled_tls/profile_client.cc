#include "profile_client.h"
#include "cert_decode.h"
static const uint16_t suites[]={0x1301,0x1302,0x1303};
static const uint16_t sigs[]={0x0904,0x0905,0x0906,0x0403,0x0804,0x0401,0x0503,0x0805,0x0501,0x0806,0x0601};
static const uint8_t alpn[]={2,'h','2',8,'h','t','t','p','/','1','.','1'};
SSL_CTX *meshvpn_profiled_context(bool configured) {
    SSL_CTX *ctx=SSL_CTX_new(TLS_client_method());
    if(!ctx)return nullptr;
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,nullptr);
    SSL_CTX_set_min_proto_version(ctx,TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx,TLS1_3_VERSION);
    if(SSL_CTX_set_alpn_protos(ctx,alpn,sizeof(alpn)))goto fail;
    if(configured){
        SSL_CTX_set_permute_extensions(ctx,0);
        SSL_CTX_enable_ocsp_stapling(ctx);
        SSL_CTX_enable_signed_cert_timestamps(ctx);
        SSL_CTX_set_grease_enabled(ctx,1);
        if(!SSL_CTX_set1_requested_trust_anchors(ctx,nullptr,0)||
           !SSL_CTX_add_cert_compression_alg(ctx,2,nullptr,meshpn_cert::decode))goto fail;
        if(!SSL_CTX_set_tls13_client_cipher_order(ctx,suites,3)||
           !SSL_CTX_set1_groups_list(ctx,"X25519MLKEM768:X25519:P-256:P-384")||
           !SSL_CTX_set_cipher_list(ctx,"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA")||
           !SSL_CTX_set_verify_algorithm_prefs(ctx,sigs,sizeof(sigs)/sizeof(sigs[0]))||
           !SSL_CTX_set_meshvpn_signature_algorithms_clienthello_wire(ctx,sigs,sizeof(sigs)/sizeof(sigs[0])))goto fail;
    }
    return ctx;
fail: SSL_CTX_free(ctx);return nullptr;
}
bool meshvpn_profiled_connection(SSL*ssl){
    static const uint16_t order[]={5,23,43,35,65281,17613,51764,13,0,11,45,27,16,65037,10,18,51};
    static const uint16_t shares[]={4588,29};
    SSL_set_enable_ech_grease(ssl,1);
    SSL_set_alps_use_new_codepoint(ssl,1);
    return SSL_set_meshpn_extension_order(ssl,order,sizeof(order)/sizeof(order[0])) &&
      SSL_set1_client_key_shares(ssl,shares,2) &&
      SSL_add_application_settings(ssl,reinterpret_cast<const uint8_t*>("h2"),2,nullptr,0);
}

static void observe_hello(int writing,int,int type,const void*data,size_t length,
                          SSL*,void*arg){
 auto* state=static_cast<meshvpn_profile_gate_state*>(arg);
 if(!writing||type!=SSL3_RT_HANDSHAKE||!length||static_cast<const uint8_t*>(data)[0]!=SSL3_MT_CLIENT_HELLO)return;
 ++state->hellos;
 state->accepted=meshvpn_profiled_tls_check(static_cast<const uint8_t*>(data),length,&state->check);
}
void meshvpn_profiled_gate_install(SSL*ssl,meshvpn_profile_gate_state*state){
 *state={};
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
bool meshvpn_profiled_attach_fd(SSL*ssl,int fd,meshvpn_profile_gate_state*state){
 // Method is immutable; the accepted flag/capture belongs to each connection.
 static bssl::UniquePtr<BIO_METHOD> method(gate_method());
 if(!ssl||!state||fd<0||!method)return false;
 BIO*b=BIO_new(method.get());if(!b)return false;
 meshvpn_profiled_gate_install(ssl,state);state->fd=fd;
 BIO_set_data(b,state);SSL_set_bio(ssl,b,b);return true;
}
