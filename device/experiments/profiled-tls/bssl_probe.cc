// Minimal BoringSSL library probe, no desktop helper/JSON IPC.
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/mem.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#ifndef ESP_PLATFORM
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
extern "C" void report_heap();
#endif
static const uint16_t suites[]={0x1301,0x1302,0x1303};
static const uint16_t sigs[]={0x0904,0x0905,0x0906,0x0403,0x0804,0x0401,0x0503,0x0805,0x0501,0x0806,0x0601};
static const uint8_t alpn[]={2,'h','2',8,'h','t','t','p','/','1','.','1'};
static SSL_CTX *config(bool configured) {
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
        if(!SSL_CTX_set_tls13_client_cipher_order(ctx,suites,3)||
           !SSL_CTX_set1_groups_list(ctx,"X25519MLKEM768:X25519:P-256:P-384")||
           !SSL_CTX_set_cipher_list(ctx,"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA")||
           !SSL_CTX_set_verify_algorithm_prefs(ctx,sigs,sizeof(sigs)/sizeof(sigs[0]))||
           !SSL_CTX_set_meshvpn_signature_algorithms_clienthello_wire(ctx,sigs,sizeof(sigs)/sizeof(sigs[0])))goto fail;
    }
    return ctx;
fail: SSL_CTX_free(ctx);return nullptr;
}
int bssl_capture(const char *file,bool configured){
    SSL_CTX*ctx=config(configured);if(!ctx)return 1;
    SSL*ssl=SSL_new(ctx);BIO*in=BIO_new(BIO_s_mem()),*out=BIO_new(BIO_s_mem());
    if(!ssl||!in||!out){SSL_free(ssl);BIO_free(in);BIO_free(out);SSL_CTX_free(ctx);return 2;}
    SSL_set_bio(ssl,in,out);SSL_set_connect_state(ssl);
    SSL_set_tlsext_host_name(ssl,"exit.meshpn.test");
    const int ret=SSL_do_handshake(ssl),error=SSL_get_error(ssl,ret);
    char*data=nullptr;long n=BIO_get_mem_data(out,&data);int result=0;
    if(error!=SSL_ERROR_WANT_READ||n<5)result=3;
    else if(file){FILE*f=fopen(file,"wb");if(!f)result=4;else{if(fwrite(data,1,(size_t)n,f)!=(size_t)n)result=4;fclose(f);}}
    else printf("ClientHello bytes=%ld (not a completed handshake)\n",n);
    SSL_free(ssl);SSL_CTX_free(ctx);return result;
}
#ifndef ESP_PLATFORM
int main(int argc,char**argv){
    atexit(report_heap);
    if(argc==4&&!strcmp(argv[1],"capture"))return bssl_capture(argv[2],!strcmp(argv[3],"prefs"));
    if(argc!=4||strcmp(argv[1],"connect"))return 2;
    SSL_CTX*ctx=config(true);if(!ctx)return 3;
    if(!SSL_CTX_load_verify_locations(ctx,argv[3],nullptr)){SSL_CTX_free(ctx);return 4;}
    int fd=socket(AF_INET,SOCK_STREAM,0);sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);addr.sin_port=htons((uint16_t)atoi(argv[2]));
    timeval timeout{5,0};
    if(fd<0||setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))||setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout))||connect(fd,(sockaddr*)&addr,sizeof(addr))){if(fd>=0)close(fd);SSL_CTX_free(ctx);return 5;}
    SSL*s=SSL_new(ctx);
    if(!s||!SSL_set_tlsext_host_name(s,"exit.meshpn.test")||!SSL_set1_host(s,"exit.meshpn.test")||!SSL_set_fd(s,fd)){SSL_free(s);SSL_CTX_free(ctx);close(fd);return 5;}
    int rc=SSL_connect(s);if(rc!=1){ERR_print_errors_fp(stderr);SSL_free(s);SSL_CTX_free(ctx);close(fd);return 6;}
    unsigned char exporter[32];const char*label="EXPORTER-clean-vpn-bind";
    if(!SSL_export_keying_material(s,exporter,32,label,strlen(label),nullptr,0,0)){SSL_free(s);SSL_CTX_free(ctx);close(fd);return 7;}
    printf("%s ",SSL_get_version(s));for(auto b:exporter)printf("%02x",b);puts("");
    SSL_shutdown(s);SSL_free(s);SSL_CTX_free(ctx);close(fd);return 0;
}
#endif
