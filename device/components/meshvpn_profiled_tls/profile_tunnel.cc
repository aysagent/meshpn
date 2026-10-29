#include "profile_tunnel.h"
#include "profile_client.h"
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <sys/select.h>
#include <fcntl.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <strings.h>
#ifdef ESP_PLATFORM
#include "esp_timer.h"
static int64_t now_us() { return esp_timer_get_time(); }
#else
#include <chrono>
static int64_t now_us() { return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count(); }
#endif

bool meshvpn_profile_http_ack(const char *h, size_t n) {
    if (!h || n < 19 || n > 4096 || memcmp(h,"HTTP/1.1 200 ",13) || memcmp(h+n-4,"\r\n\r\n",4)) return false;
    for(size_t i=0;i<n;i++) if((unsigned char)h[i]>=127 || ((unsigned char)h[i]<32 && h[i]!='\r' && h[i]!='\n' && h[i]!='\t')) return false;
    size_t pos=0; bool type=false;
    while(pos+1<n && !(h[pos]=='\r' && h[pos+1]=='\n')) pos++;
    for(size_t i=0;i<pos;i++)if((unsigned char)h[i]<32)return false;
    pos+=2;
    while(pos+2<n) {
        size_t end=pos;
        while(end+1<n && !(h[end]=='\r' && h[end+1]=='\n')) end++;
        if(end+1>=n || h[pos]==' ' || h[pos]=='\t')return false;
        const char *colon=static_cast<const char*>(memchr(h+pos,':',end-pos));
        if(!colon)return false;
        size_t key=colon-(h+pos),start=colon-h+1,finish=end;
        if(!key)return false;
        for(size_t i=pos;i<end;i++)if(h[i]=='\r'||h[i]=='\n')return false;
        for(size_t i=0;i<key;i++) {
            char ch=h[pos+i];
            if(!((ch>='a'&&ch<='z')||(ch>='A'&&ch<='Z')||(ch>='0'&&ch<='9')||ch=='-'))return false;
        }
        while(start<finish && (h[start]==' '||h[start]=='\t'))start++;
        while(finish>start && (h[finish-1]==' '||h[finish-1]=='\t'))finish--;
        if(key==12 && !strncasecmp(h+pos,"content-type",12)) {
            if(type || finish-start!=24 || strncasecmp(h+start,"application/octet-stream",24))return false;
            type=true;
        }
        // Tunnel switches to raw framing; framed/chunked HTTP bodies are not ACKs.
        if((key==14 && !strncasecmp(h+pos,"content-length",14)) ||
           (key==17 && !strncasecmp(h+pos,"transfer-encoding",17)))return false;
        pos=end+2;
    }
    return type && pos==n-2;
}
namespace {
struct Connection {
    const meshvpn_profile_tunnel_options_t &o;
    bssl::UniquePtr<SSL_CTX> ctx;
    bssl::UniquePtr<SSL> ssl;
    meshvpn_profile_gate_state gate;
    meshvpn_profile_tunnel_diag_t diag{};
    void report(const char *phase,int error=0) {
        snprintf(diag.phase,sizeof(diag.phase),"%s",phase);
        diag.error=error; diag.actual=gate.check; diag.hellos=gate.hellos;
        diag.tls_bytes_sent=gate.sent_bytes;
        if(ssl)diag.verify_error=SSL_get_verify_result(ssl.get());
        if(o.diagnostic)o.diagnostic(o.arg,&diag);
    }
    bool current() { return o.current(o.arg); }
    int wait(int want,int64_t deadline) {
        if(!current())return ECANCELED;
        if(now_us()>=deadline)return ETIMEDOUT;
        fd_set rd,wr;FD_ZERO(&rd);FD_ZERO(&wr);
        if(want==SSL_ERROR_WANT_WRITE)FD_SET(o.fd,&wr);else FD_SET(o.fd,&rd);
        timeval tv{0,10000};
        int rc=select(o.fd+1,&rd,&wr,nullptr,&tv);
        if(rc<0 && errno!=EINTR)return errno;
        return current()?0:ECANCELED;
    }
    int tls_error(int result) {
        int e=SSL_get_error(ssl.get(),result);diag.ssl_error=e;return e;
    }
    int failure(const char *phase,int e) { diag.authenticated=false; report(phase,e);return e; }
};
static bool wants(int e) {return e==SSL_ERROR_WANT_READ||e==SSL_ERROR_WANT_WRITE;}
static int hex(char c) { if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1; }
static bool bearer(SSL *ssl,const char *key,char out[33]) {
    uint8_t psk[32]{},ek[32]{},message[96]{},mac[32]{};bool ok=false;
    if(!key || strlen(key)!=64 || time(nullptr)<1704067200)return false;
    for(size_t i=0;i<32;i++){int a=hex(key[2*i]),b=hex(key[2*i+1]);if(a<0||b<0){OPENSSL_cleanse(psk,sizeof(psk));return false;}psk[i]=(a<<4)|b;}
    const char *label="EXPORTER-clean-vpn-bind",*prefix="clean-vpn-tls-v2:";
    if(SSL_export_keying_material(ssl,ek,sizeof(ek),label,strlen(label),nullptr,0,0)) {
        size_t used=strlen(prefix);memcpy(message,prefix,used);memcpy(message+used,ek,sizeof(ek));used+=sizeof(ek);
        int n=snprintf(reinterpret_cast<char*>(message+used),sizeof(message)-used,":%lld",static_cast<long long>(time(nullptr)/900));
        unsigned length=0;
        if(n>0 && static_cast<size_t>(n)<sizeof(message)-used && HMAC(EVP_sha256(),psk,sizeof(psk),message,used+n,mac,&length) && length==32) {
            for(size_t i=0;i<16;i++) { snprintf(out+2*i,3,"%02x",mac[i]); }
            ok=true;
        }
    }
    OPENSSL_cleanse(psk,sizeof(psk));OPENSSL_cleanse(ek,sizeof(ek));OPENSSL_cleanse(message,sizeof(message));OPENSSL_cleanse(mac,sizeof(mac));return ok;
}
static bool load_ca(SSL_CTX *ctx,const char *pem) {
    if(!pem || !*pem || strlen(pem)>8192)return false;
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem,strlen(pem)));if(!bio)return false;
    unsigned count=0;
    while(auto *raw=PEM_read_bio_X509(bio.get(),nullptr,nullptr,nullptr)) {
        bssl::UniquePtr<X509> cert(raw);
        if(!X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx),cert.get()))return false;
        count++;
    }
    ERR_clear_error();return count>0;
}
}
int meshvpn_profile_tunnel_run(const meshvpn_profile_tunnel_options_t *options) {
    if(!options)return EINVAL;
    const auto &o=*options;
    if(o.fd<0||o.fd>=FD_SETSIZE||!o.current||!o.peek||!o.sent||!o.receive||!o.ready||!o.healthy)return EINVAL;
    Connection c{o,{},{},{},{}};
    c.report("starting");
    if(!o.profile||strcmp(o.profile,MESHPN_TLS_PROFILE_ID))return c.failure("unsupported_profile",EINVAL);
    if(!o.name || !*o.name || strlen(o.name)>128)return c.failure("server_name",EINVAL);
    for(const char *p=o.name;*p;p++)if(!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||*p=='.'||*p=='-'))return c.failure("server_name",EINVAL);
    if(time(nullptr)<1704067200)return c.failure("clock",EAGAIN);
    int flags=fcntl(o.fd,F_GETFL,0);if(flags<0 || !(flags&O_NONBLOCK))return c.failure("nonblocking_required",EINVAL);
    if(!c.current())return c.failure("cancelled",ECANCELED);
    c.ctx.reset(meshvpn_profiled_context(true));
    if(!c.ctx)return c.failure("no_memory",ENOMEM);
    if(!load_ca(c.ctx.get(),o.ca_pem))return c.failure("ca_invalid",EACCES);
    c.ssl.reset(SSL_new(c.ctx.get()));
    if(!c.ssl || !meshvpn_profiled_connection(c.ssl.get()) ||
       !SSL_set_tlsext_host_name(c.ssl.get(),o.name) || !SSL_set1_host(c.ssl.get(),o.name) ||
       !meshvpn_profiled_attach_fd(c.ssl.get(),o.fd,&c.gate))return c.failure("tls_setup",ENOMEM);
    c.report("handshake");int64_t deadline=now_us()+10000000;
    for(;;) {
        if(!c.current())return c.failure("cancelled",ECANCELED);
        int rc=SSL_connect(c.ssl.get());
        if(rc==1)break;
        int e=c.tls_error(rc);
        if(c.gate.hellos&&!c.gate.accepted)return c.failure("profile_mismatch",EPROTO);
        if(!wants(e))return c.failure("tls_handshake",EACCES);
        if((e=c.wait(e,deadline)))return c.failure("handshake_wait",e);
    }
    c.diag.ssl_error=0;
    if(!c.gate.accepted||!c.gate.hellos)return c.failure("profile_unverified",EPROTO);
    if(SSL_get_verify_result(c.ssl.get())!=X509_V_OK)return c.failure("certificate",EACCES);
    if(SSL_version(c.ssl.get())!=TLS1_3_VERSION)return c.failure("tls_version",EPROTO);
    const uint8_t *alpn=nullptr;unsigned alpn_len=0;SSL_get0_alpn_selected(c.ssl.get(),&alpn,&alpn_len);
    snprintf(c.diag.alpn,sizeof(c.diag.alpn),"%.*s",static_cast<int>(alpn_len),alpn_len?reinterpret_cast<const char*>(alpn):"");
    if(alpn_len!=8||memcmp(alpn,"http/1.1",8))return c.failure("exit_requires_http1",EPROTONOSUPPORT);
    char token[33]{},request[640]{};
    if(!bearer(c.ssl.get(),o.psk_hex,token))return c.failure("exporter_or_key",EACCES);
    int request_len=snprintf(request,sizeof(request),"GET /clean-vpn HTTP/1.1\r\nHost: %s\r\nUser-Agent: MeshPN/1\r\nAccept: */*\r\nAuthorization: Bearer %s\r\nConnection: keep-alive\r\n\r\n",o.name,token);
    OPENSSL_cleanse(token,sizeof(token));
    if(request_len<=0 || static_cast<size_t>(request_len)>=sizeof(request)) { OPENSSL_cleanse(request,sizeof(request)); return c.failure("request_size",EINVAL); }
    c.report("authenticating");deadline=now_us()+5000000;
    size_t used=0;int auth_error=0;
    while(used<static_cast<size_t>(request_len)) {
        if(!c.current()){auth_error=ECANCELED;break;}
        int rc=SSL_write(c.ssl.get(),request+used,request_len-used);
        if(rc>0){used+=rc;continue;}
        int e=c.tls_error(rc);if(!wants(e)){auth_error=EPROTO;break;}
        if((auth_error=c.wait(e,deadline)))break;
    }
    OPENSSL_cleanse(request,sizeof(request));
    if(auth_error)return c.failure("auth_write",auth_error);
    bssl::UniquePtr<uint8_t> buffer(static_cast<uint8_t*>(OPENSSL_malloc(MESHPN_PROFILE_READ_BYTES)));
    if(!buffer)return c.failure("no_memory",ENOMEM);
    used=0;
    // Read only headers. Bytes coalesced after the ACK remain in SSL's buffer.
    while(used<4096) {
        if(!c.current())return c.failure("cancelled",ECANCELED);
        int rc=SSL_read(c.ssl.get(),buffer.get()+used,1);
        if(rc>0){used++;if(used>=4&&!memcmp(buffer.get()+used-4,"\r\n\r\n",4))break;}
        else {int e=c.tls_error(rc);if(!wants(e))return c.failure("auth_read",EACCES);if((e=c.wait(e,deadline)))return c.failure("auth_wait",e);}
        if(now_us()>=deadline)return c.failure("auth_timeout",ETIMEDOUT);
    }
    if(!meshvpn_profile_http_ack(reinterpret_cast<char*>(buffer.get()),used))return c.failure("auth_rejected",EACCES);
    if(!c.current())return c.failure("cancelled",ECANCELED);
    c.diag.ssl_error=0;c.diag.authenticated=true;c.report("up");o.ready(o.arg);
    const uint8_t *tx=nullptr;size_t tx_len=0;int64_t tx_deadline=0;
    int write_want=SSL_ERROR_WANT_WRITE,read_want=SSL_ERROR_WANT_READ;
    while(c.current()) {
        if(!o.healthy(o.arg))return c.failure("packet_path",EIO);
        bool progressed=false;
        if(!tx_len){tx_len=o.peek(o.arg,&tx);if(tx_len){if(!tx)return c.failure("tx_buffer",EINVAL);if(tx_len>16384)tx_len=16384;tx_deadline=now_us()+5000000;}}
        if(tx_len) {
            if(!c.current())break;
            int rc=SSL_write(c.ssl.get(),tx,tx_len);
            if(rc>0){o.sent(o.arg,rc);tx_len=0;progressed=true;write_want=SSL_ERROR_WANT_WRITE;}
            else {write_want=c.tls_error(rc);if(!wants(write_want))return c.failure("tls_write",EPIPE);}
            if(tx_len&&now_us()>=tx_deadline)return c.failure("tx_timeout",ETIMEDOUT);
        }
        if(!c.current())break;
        int rc=SSL_read(c.ssl.get(),buffer.get(),MESHPN_PROFILE_READ_BYTES);
        if(rc>0){if(!o.receive(o.arg,buffer.get(),rc))return c.failure("invalid_frame",EPROTO);progressed=true;read_want=SSL_ERROR_WANT_READ;}
        else {read_want=c.tls_error(rc);if(!wants(read_want))return c.failure("tls_read",ECONNRESET);}
        if(!progressed){
            fd_set rd,wr;FD_ZERO(&rd);FD_ZERO(&wr);FD_SET(o.fd,&rd);
            if((tx_len&&write_want==SSL_ERROR_WANT_WRITE)||read_want==SSL_ERROR_WANT_WRITE)FD_SET(o.fd,&wr);
            timeval tv{0,10000};int e=select(o.fd+1,&rd,&wr,nullptr,&tv);
            if(e<0&&errno!=EINTR)return c.failure("io_wait",errno);
        }
    }
    return c.failure("cancelled",ECANCELED);
}
