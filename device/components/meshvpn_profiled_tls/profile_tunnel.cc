#include "profile_tunnel.h"
#include "profile_client.h"
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <nghttp2/nghttp2.h>
#include <algorithm>
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

// Single-stream clean-vpn HTTP/2. nghttp2 owns HPACK, frame validation,
// SETTINGS/PING ACK and both flow-control windows; TLS and I/O stay on this task.
struct Http2 {
    Connection &c;
    nghttp2_session *session=nullptr;
    int32_t stream=-1;
    int error=0;
    const char *phase="h2_protocol";
    bool status=false,type=false;
    size_t header_bytes=0,header_count=0,staged=0;
    explicit Http2(Connection &connection):c(connection) {}
    ~Http2(){nghttp2_session_del(session);}
    int fail(const char *p,int e=EPROTO) {phase=p;error=e;return NGHTTP2_ERR_CALLBACK_FAILURE;}
    int lib_error(int e) {c.diag.http2_error=e;return fail(e==NGHTTP2_ERR_NOMEM?"no_memory":"h2_protocol",e==NGHTTP2_ERR_NOMEM?ENOMEM:EPROTO);}
    static Http2 &get(void *p){return *static_cast<Http2*>(p);}
    static bool equal(const uint8_t *p,size_t n,const char *v){return n==strlen(v)&&!memcmp(p,v,n);}
    static int begin(nghttp2_session*,const nghttp2_frame *f,void *p) {
        auto &h=get(p);
        if(f->hd.stream_id!=h.stream || f->headers.cat!=NGHTTP2_HCAT_RESPONSE || h.c.diag.authenticated)
            return h.fail("h2_unexpected_headers");
        h.status=h.type=false;h.header_bytes=h.header_count=0;return 0;
    }
    static int header(nghttp2_session*,const nghttp2_frame*,const uint8_t *name,size_t nn,
                      const uint8_t *value,size_t vn,uint8_t,void *p) {
        auto &h=get(p);
        if(nn>4096 || vn>4096 || nn+vn>4096-h.header_bytes || ++h.header_count>64)
            return h.fail("h2_headers_limit");
        h.header_bytes+=nn+vn;
        if(equal(name,nn,":status")) {
            if(h.status || !equal(value,vn,"200"))return h.fail("auth_rejected",EACCES);
            h.status=true;
        } else if(equal(name,nn,"content-type")) {
            if(h.type || vn!=24 || strncasecmp(reinterpret_cast<const char*>(value),"application/octet-stream",vn))
                return h.fail("auth_rejected",EACCES);
            h.type=true;
        } else if(equal(name,nn,"content-length") || equal(name,nn,"transfer-encoding"))
            return h.fail("auth_rejected",EACCES);
        return 0;
    }
    static int frame(nghttp2_session*,const nghttp2_frame *f,void *p) {
        auto &h=get(p);
        if(!h.c.current())return h.fail("cancelled",ECANCELED);
        if(f->hd.type==NGHTTP2_GOAWAY)return h.fail("h2_goaway",ECONNRESET);
        if(f->hd.type==NGHTTP2_PUSH_PROMISE)return h.fail("h2_push");
        if(f->hd.stream_id!=h.stream)return 0;
        if(f->hd.type==NGHTTP2_RST_STREAM)return h.fail("h2_reset",ECONNRESET);
        if((f->hd.type==NGHTTP2_HEADERS || f->hd.type==NGHTTP2_DATA) && (f->hd.flags&NGHTTP2_FLAG_END_STREAM))
            return h.fail("h2_end_stream",ECONNRESET);
        if(f->hd.type==NGHTTP2_HEADERS) {
            if(!h.status||!h.type)return h.fail("auth_rejected",EACCES);
            h.c.diag.ssl_error=0;h.c.diag.authenticated=true;h.c.report("up");h.c.o.ready(h.c.o.arg);
        }
        return 0;
    }
    static int invalid(nghttp2_session*,const nghttp2_frame*,int e,void *p){return get(p).lib_error(e);}
    static int sending(nghttp2_session*,const nghttp2_frame *f,void *p) {
        // nghttp2 can queue GOAWAY internally rather than call invalid(). Do
        // not leave the VPN marked up after its HTTP/2 session has terminated.
        auto &h=get(p);
        if(f->hd.type==NGHTTP2_GOAWAY) {
            h.c.diag.http2_error=static_cast<int>(f->goaway.error_code);
            return h.fail("h2_protocol");
        }
        return 0;
    }
    static int closed(nghttp2_session*,int32_t stream,uint32_t,void *p) {
        auto &h=get(p);if(stream==h.stream && !h.error)h.fail("h2_stream_closed",ECONNRESET);return 0;
    }
    static int data(nghttp2_session*,uint8_t,int32_t stream,const uint8_t *bytes,size_t n,void *p) {
        auto &h=get(p);
        if(!h.c.current())return h.fail("cancelled",ECANCELED);
        if(stream!=h.stream || !h.c.diag.authenticated)return h.fail("h2_data_before_ack");
        if(n && !h.c.o.receive(h.c.o.arg,bytes,n))return h.fail("invalid_frame");
        return 0;
    }
    static nghttp2_ssize provide(nghttp2_session*,int32_t,uint8_t *buffer,size_t length,
                                 uint32_t*,nghttp2_data_source*,void *p) {
        auto &h=get(p);
        if(!h.c.current())return h.fail("cancelled",ECANCELED);
        if(!h.c.diag.authenticated)return NGHTTP2_ERR_DEFERRED;
        const uint8_t *bytes=nullptr;size_t n=h.c.o.peek(h.c.o.arg,&bytes);
        if(!n)return NGHTTP2_ERR_DEFERRED;
        if(!bytes||h.staged)return h.fail("h2_tx_buffer");
        n=std::min(n,std::min(length,size_t(MESHPN_PROFILE_READ_BYTES)));
        memcpy(buffer,bytes,n);h.staged=n;
        // Do not advance the VPN queue until these framed bytes reach SSL_write.
        // No EOF: request DATA remains open in both directions for the session.
        return static_cast<nghttp2_ssize>(n);
    }
    static void *alloc(size_t n,void*){return OPENSSL_malloc(n);}
    static void release(void *p,void*){OPENSSL_free(p);}
    static void *resize(void *p,size_t n,void*){return OPENSSL_realloc(p,n);}
    static void *zero(size_t n,size_t size,void*) {
        if(size && n>SIZE_MAX/size)return nullptr;
        return OPENSSL_zalloc(n*size);
    }
    int setup(const char *token) {
        nghttp2_session_callbacks *cb=nullptr;nghttp2_option *opt=nullptr;
        if(nghttp2_session_callbacks_new(&cb))return lib_error(NGHTTP2_ERR_NOMEM);
        if(nghttp2_option_new(&opt)){nghttp2_session_callbacks_del(cb);return lib_error(NGHTTP2_ERR_NOMEM);}
        nghttp2_session_callbacks_set_on_begin_headers_callback(cb,begin);
        nghttp2_session_callbacks_set_on_header_callback(cb,header);
        nghttp2_session_callbacks_set_on_frame_recv_callback(cb,frame);
        nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(cb,invalid);
        nghttp2_session_callbacks_set_on_frame_not_send_callback(cb,invalid);
        nghttp2_session_callbacks_set_on_frame_send_callback(cb,sending);
        nghttp2_session_callbacks_set_on_stream_close_callback(cb,closed);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb,data);
        nghttp2_option_set_max_send_header_block_length(opt,4096);
        nghttp2_option_set_max_deflate_dynamic_table_size(opt,4096);
        nghttp2_option_set_max_settings(opt,32);
        nghttp2_option_set_max_outbound_ack(opt,16);
        nghttp2_option_set_max_continuations(opt,8);
        nghttp2_mem memory{nullptr,alloc,release,zero,resize};
        int rc=nghttp2_session_client_new3(&session,cb,this,opt,&memory);
        nghttp2_session_callbacks_del(cb);nghttp2_option_del(opt);
        if(rc)return lib_error(rc);
        const nghttp2_settings_entry settings[]={
            {NGHTTP2_SETTINGS_ENABLE_PUSH,0},{NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,4096},
            {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,262144},{NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,4096}};
        if((rc=nghttp2_submit_settings(session,NGHTTP2_FLAG_NONE,settings,4)) ||
           (rc=nghttp2_session_set_local_window_size(session,NGHTTP2_FLAG_NONE,0,262144)))return lib_error(rc);
        char authorization[40];snprintf(authorization,sizeof(authorization),"Bearer %s",token);
        auto nv=[](const char *name,const char *value,uint8_t flags=NGHTTP2_NV_FLAG_NONE) {
            return nghttp2_nv{reinterpret_cast<uint8_t*>(const_cast<char*>(name)),reinterpret_cast<uint8_t*>(const_cast<char*>(value)),strlen(name),strlen(value),flags};
        };
        const nghttp2_nv headers[]={nv(":method","POST"),nv(":scheme","https"),
            nv(":authority",c.o.name),nv(":path","/clean-vpn"),
            nv("authorization",authorization,NGHTTP2_NV_FLAG_NO_INDEX),nv("user-agent","MeshPN/1"),nv("accept","*/*")};
        nghttp2_data_provider2 provider{};provider.read_callback=provide;
        stream=nghttp2_submit_request2(session,nullptr,headers,7,&provider,nullptr);
        OPENSSL_cleanse(authorization,sizeof(authorization));
        return stream<0?lib_error(stream):0;
    }
    int run() {
        bssl::UniquePtr<uint8_t> buffer(static_cast<uint8_t*>(OPENSSL_malloc(MESHPN_PROFILE_READ_BYTES)));
        if(!buffer)return c.failure("no_memory",ENOMEM);
        const uint8_t *out=nullptr;size_t left=0;
        int read_want=SSL_ERROR_WANT_READ,write_want=SSL_ERROR_WANT_WRITE;
        int64_t auth_deadline=now_us()+5000000,write_deadline=0,flow_deadline=0;
        c.report("h2_authenticating");
        while(c.current()) {
            if(!c.o.healthy(c.o.arg))return c.failure("packet_path",EIO);
            if(error)return c.failure(phase,error);
            if(!c.diag.authenticated && now_us()>=auth_deadline)return c.failure("auth_timeout",ETIMEDOUT);
            if(c.diag.authenticated) {
                const uint8_t *unused=nullptr;size_t queued=c.o.peek(c.o.arg,&unused);
                if(queued) {if(!flow_deadline)flow_deadline=now_us()+5000000;}
                else flow_deadline=0;
                // Resuming a non-deferred stream is a harmless INVALID_ARGUMENT.
                int rc=nghttp2_session_resume_data(session,stream);
                if(rc && rc!=NGHTTP2_ERR_INVALID_ARGUMENT)lib_error(rc);
            }
            if(error)return c.failure(phase,error);
            bool progress=false;
            if(!left) {
                nghttp2_ssize n=nghttp2_session_mem_send2(session,&out);
                if(error)return c.failure(phase,error);
                if(n<0){lib_error(static_cast<int>(n));return c.failure(phase,error);}
                left=static_cast<size_t>(n);
                if(left)write_deadline=now_us()+5000000;
                else if(!nghttp2_session_want_read(session) && !nghttp2_session_want_write(session))
                    return c.failure("h2_session_closed",ECONNRESET);
            }
            if(left) {
                if(!c.current())break;
                int n=SSL_write(c.ssl.get(),out,left);
                if(n>0) {
                    out+=n;left-=n;progress=true;write_want=SSL_ERROR_WANT_WRITE;
                    if(!left && staged) {c.o.sent(c.o.arg,staged);staged=0;flow_deadline=0;}
                } else {write_want=c.tls_error(n);if(!wants(write_want))return c.failure("tls_write",EPIPE);}
                if(left && now_us()>=write_deadline)return c.failure("tx_timeout",ETIMEDOUT);
            }
            if(flow_deadline && now_us()>=flow_deadline)return c.failure("h2_flow_timeout",ETIMEDOUT);
            if(!c.current())break;
            int n=SSL_read(c.ssl.get(),buffer.get(),MESHPN_PROFILE_READ_BYTES);
            if(n>0) {
                nghttp2_ssize used=nghttp2_session_mem_recv2(session,buffer.get(),n);
                if(error)return c.failure(phase,error);
                if(used!=n) {lib_error(used<0?static_cast<int>(used):NGHTTP2_ERR_PROTO);return c.failure(phase,error);}
                progress=true;read_want=SSL_ERROR_WANT_READ;
            } else {read_want=c.tls_error(n);if(!wants(read_want))return c.failure("tls_read",ECONNRESET);}
            if(!progress) {
                fd_set rd,wr;FD_ZERO(&rd);FD_ZERO(&wr);FD_SET(c.o.fd,&rd);
                if((left&&write_want==SSL_ERROR_WANT_WRITE)||read_want==SSL_ERROR_WANT_WRITE)FD_SET(c.o.fd,&wr);
                timeval tv{0,10000};int rc=select(c.o.fd+1,&rd,&wr,nullptr,&tv);
                if(rc<0&&errno!=EINTR)return c.failure("io_wait",errno);
            }
        }
        return c.failure("cancelled",ECANCELED);
    }
};
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
    bool http2=alpn_len==2&&!memcmp(alpn,"h2",2);
    if(!http2 && (alpn_len!=8||memcmp(alpn,"http/1.1",8)))return c.failure("unsupported_alpn",EPROTONOSUPPORT);
    char token[33]{},request[640]{};
    if(!bearer(c.ssl.get(),o.psk_hex,token))return c.failure("exporter_or_key",EACCES);
    if(http2) {
        // JS clean-vpn does not send ALPS. Do not silently ignore a different
        // server's negotiated HTTP/2 settings; that needs an ALPS adapter.
        const uint8_t *settings=nullptr;size_t length=0;
        SSL_get0_peer_application_settings(c.ssl.get(),&settings,&length);
        if(length){OPENSSL_cleanse(token,sizeof(token));return c.failure("h2_alps_unsupported",EPROTONOSUPPORT);}
        Http2 h(c);int rc=h.setup(token);OPENSSL_cleanse(token,sizeof(token));
        if(rc)return c.failure(h.phase,h.error);
        return h.run();
    }
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
