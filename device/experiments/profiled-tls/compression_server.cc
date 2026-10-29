#include <openssl/ssl.h>
#include <openssl/bytestring.h>
#include <cstring>
#include <openssl/err.h>
#include <brotli/encode.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <vector>
static unsigned compressed_count=0;
static int compress_cert(SSL*,CBB*out,const uint8_t*data,size_t length){
 if(length>65536)return 0;
 std::vector<uint8_t> b(BrotliEncoderMaxCompressedSize(length));size_t n=b.size();
 if(!BrotliEncoderCompress(5,BROTLI_DEFAULT_WINDOW,BROTLI_MODE_GENERIC,length,data,&n,b.data()))return 0;
 ++compressed_count;return CBB_add_bytes(out,b.data(),n);
}
static int select_alpn(SSL*,const uint8_t**out,uint8_t*len,const uint8_t*in,unsigned n,void*){
 static const uint8_t prefs[]={2,'h','2'};
 return SSL_select_next_proto(const_cast<uint8_t**>(out),len,prefs,sizeof(prefs),in,n)==OPENSSL_NPN_NEGOTIATED?SSL_TLSEXT_ERR_OK:SSL_TLSEXT_ERR_ALERT_FATAL;
}
int main(int argc,char**argv){
 if(argc!=3)return 2;
 SSL_CTX*ctx=SSL_CTX_new(TLS_server_method());
 if(!ctx||!SSL_CTX_use_certificate_chain_file(ctx,argv[1])||!SSL_CTX_use_PrivateKey_file(ctx,argv[2],SSL_FILETYPE_PEM)||!SSL_CTX_set_min_proto_version(ctx,TLS1_3_VERSION)||!SSL_CTX_add_cert_compression_alg(ctx,2,compress_cert,nullptr))return 3;
 SSL_CTX_set_alpn_select_cb(ctx,select_alpn,nullptr);
 int listener=socket(AF_INET,SOCK_STREAM,0);sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 if(bind(listener,(sockaddr*)&addr,sizeof(addr))||listen(listener,4))return 4;
 socklen_t len=sizeof(addr);getsockname(listener,(sockaddr*)&addr,&len);printf("PORT %u\n",ntohs(addr.sin_port));fflush(stdout);
 for(int i=0;i<3;i++){
  int fd=accept(listener,nullptr,nullptr);if(fd<0)return 5;
  timeval timeout{5,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
  SSL*s=SSL_new(ctx);SSL_set_fd(s,fd);SSL_set_alps_use_new_codepoint(s,1);
  if(!SSL_add_application_settings(s,reinterpret_cast<const uint8_t*>("h2"),2,nullptr,0)||SSL_accept(s)!=1){ERR_print_errors_fp(stderr);return 6;}
  if(!SSL_has_application_settings(s))return 7;
  uint8_t exporter[32];const char*label="EXPORTER-clean-vpn-bind";
  if(!SSL_export_keying_material(s,exporter,32,label,strlen(label),nullptr,0,0))return 8;
  printf("EXPORTER ");for(auto b:exporter)printf("%02x",b);printf(" compressed=%u alps=1\n",compressed_count);fflush(stdout);
  SSL_shutdown(s);SSL_free(s);close(fd);
 }
 close(listener);SSL_CTX_free(ctx);return compressed_count==3?0:9;
}
