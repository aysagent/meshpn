// Minimal BoringSSL library probe, no desktop helper/JSON IPC.
#include <openssl/ssl.h>
#include "profile_client.h"
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
int bssl_capture(const char *file,bool configured){
    SSL_CTX*ctx=meshvpn_profiled_context(configured);if(!ctx)return 1;
    SSL*ssl=SSL_new(ctx);BIO*in=BIO_new(BIO_s_mem()),*out=BIO_new(BIO_s_mem());
    if(!ssl||!in||!out){SSL_free(ssl);BIO_free(in);BIO_free(out);SSL_CTX_free(ctx);return 2;}
    SSL_set_bio(ssl,in,out);SSL_set_connect_state(ssl);
    meshvpn_profile_gate_state gate;
    if(configured)meshvpn_profiled_gate_install(ssl,&gate);
    if(configured&&!meshvpn_profiled_connection(ssl)){SSL_free(ssl);SSL_CTX_free(ctx);return 2;}
    SSL_set_tlsext_host_name(ssl,"exit.meshpn.test");
    const int ret=SSL_do_handshake(ssl),error=SSL_get_error(ssl,ret);
    char*data=nullptr;long n=BIO_get_mem_data(out,&data);int result=0;
    if(error!=SSL_ERROR_WANT_READ||n<5||(configured&&!gate.accepted))result=3;
    else if(file){FILE*f=fopen(file,"wb");if(!f)result=4;else{if(fwrite(data,1,(size_t)n,f)!=(size_t)n)result=4;fclose(f);}}
    else printf("ClientHello bytes=%ld (not a completed handshake)\n",n);
    SSL_free(ssl);SSL_CTX_free(ctx);return result;
}
#ifndef ESP_PLATFORM
int main(int argc,char**argv){
    atexit(report_heap);
    if(argc==4&&!strcmp(argv[1],"capture"))return bssl_capture(argv[2],!strcmp(argv[3],"prefs"));
    if(argc!=4||strcmp(argv[1],"connect"))return 2;
    SSL_CTX*ctx=meshvpn_profiled_context(true);if(!ctx)return 3;
    const char*mutate=getenv("MESHPN_PROFILE_MUTATE");
    if(mutate&&!strcmp(mutate,"signature_order")){
        const uint16_t changed[]={0x0905,0x0904,0x0906,0x0403,0x0804,0x0401,0x0503,0x0805,0x0501,0x0806,0x0601};
        if(!SSL_CTX_set_meshvpn_signature_algorithms_clienthello_wire(ctx,changed,11)){SSL_CTX_free(ctx);return 3;}
    }
    if(!SSL_CTX_load_verify_locations(ctx,argv[3],nullptr)){SSL_CTX_free(ctx);return 4;}
    int fd=socket(AF_INET,SOCK_STREAM,0);sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);addr.sin_port=htons((uint16_t)atoi(argv[2]));
    timeval timeout{5,0};
    if(fd<0||setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))||setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout))||connect(fd,(sockaddr*)&addr,sizeof(addr))){if(fd>=0)close(fd);SSL_CTX_free(ctx);return 5;}
    SSL*s=SSL_new(ctx);meshvpn_profile_gate_state gate;
    if(!s||!meshvpn_profiled_connection(s)||!SSL_set_tlsext_host_name(s,"exit.meshpn.test")||!SSL_set1_host(s,"exit.meshpn.test")||!meshvpn_profiled_attach_fd(s,fd,&gate)){SSL_free(s);SSL_CTX_free(ctx);close(fd);return 5;}
    if(mutate){
      if(!strcmp(mutate,"alpn")){const uint8_t bad[]={8,'h','t','t','p','/','1','.','1'};SSL_set_alpn_protos(s,bad,sizeof(bad));}
      else if(!strcmp(mutate,"order")){const uint16_t bad[]={23,5,43,35,65281,17613,51764,13,0,11,45,27,16,65037,10,18,51};SSL_set_meshpn_extension_order(s,bad,17);}
      else if(!strcmp(mutate,"no_gate")){SSL_set_msg_callback(s,nullptr);}
      else if(strcmp(mutate,"signature_order"))return 2;
    }
    int rc=SSL_connect(s);
    fprintf(stderr,"PROFILE_GATE hellos=%u match=%u sent=%zu ja3=%s ja4=%s\n",gate.hellos,gate.accepted,gate.sent_bytes,gate.check.ja3,gate.check.ja4);if(rc!=1){ERR_print_errors_fp(stderr);SSL_free(s);SSL_CTX_free(ctx);close(fd);return 6;}
    unsigned char exporter[32];const char*label="EXPORTER-clean-vpn-bind";
    if(!SSL_export_keying_material(s,exporter,32,label,strlen(label),nullptr,0,0)){SSL_free(s);SSL_CTX_free(ctx);close(fd);return 7;}
    printf("%s ",SSL_get_version(s));for(auto b:exporter)printf("%02x",b);puts("");
    SSL_shutdown(s);SSL_free(s);SSL_CTX_free(ctx);close(fd);return 0;
}
#endif
