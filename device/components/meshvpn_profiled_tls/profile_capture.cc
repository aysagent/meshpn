#include "profile_capture.h"
#include <openssl/sha.h>
#include <cstring>
#include <strings.h>
namespace {
struct Cursor{
 const uint8_t*p;size_t n;
 bool byte(uint8_t&v){if(!n)return false;v=*p++;n--;return true;}
 bool word(uint16_t&v){if(n<2)return false;v=(uint16_t(p[0])<<8)|p[1];p+=2;n-=2;return true;}
 bool skip(size_t k){if(k>n)return false;p+=k;n-=k;return true;}
 bool sub(size_t k,Cursor&v){if(k>n)return false;v={p,k};p+=k;n-=k;return true;}
};
bool grease(uint16_t n){return (n&0x0f0f)==0x0a0a&&(n>>8)==(n&255);}
bool add(meshpn_profile_ids_t&a,uint16_t v){
 if(grease(v))return true;
 if(a.count==32)return false;
 for(unsigned i=0;i<a.count;i++)if(a.values[i]==v)return false;
 a.values[a.count++]=v;return true;
}
bool ids(Cursor c,meshpn_profile_ids_t&a){while(c.n){uint16_t v;if(!c.word(v)||!add(a,v))return false;}return true;}
bool vector16(Cursor c,meshpn_profile_ids_t&a){uint16_t n;return c.word(n)&&n==c.n&&ids(c,a);}
}
bool meshpn_profile_from_hello(const uint8_t*h,size_t n,const char*host,const char*name,meshpn_tls_profile_t*out,const char**reason){
 if(!out||!reason)return false;
 *reason="Malformed or oversized ClientHello";memset(out,0,sizeof(*out));
 if(!h||n<42||n>8192||!host||!name||!strlen(name)||strlen(name)>64)return false;
 for(const unsigned char*p=(const unsigned char*)name;*p;p++)if(*p<32||*p==127)return false;
 meshvpn_profile_check_t hashes{};
 (void)meshvpn_profiled_tls_check_expected(h,n,"","",&hashes);
 if(!*hashes.ja3||!*hashes.ja4){*reason="Requires hostname SNI, TLS 1.3 and h2-first ALPN";return false;}
 Cursor c{h+4,n-4},v{};uint8_t b;uint16_t z;
 if(!c.skip(34)||!c.byte(b)||!c.skip(b)||!c.word(z)||!c.sub(z,v))return false;
 for(size_t i=0;i+1<v.n;i+=2)if(grease((uint16_t(v.p[i])<<8)|v.p[i+1]))out->grease=true;
 if(!ids(v,out->ciphers)||!c.byte(b)||!c.skip(b)||!c.word(z)||z!=c.n||!c.sub(z,v))return false;
 bool sni=false;
 while(v.n){
  uint16_t type,len;Cursor e{};
  if(!v.word(type)||!v.word(len)||!v.sub(len,e))return false;
  if(grease(type))continue;
  if(!add(out->extensions,type))return false;
  switch(type){
   case 0:{
    uint16_t list,hostlen;uint8_t kind;
    if(!e.word(list)||list!=e.n||!e.byte(kind)||kind||!e.word(hostlen)||hostlen!=e.n||hostlen!=strlen(host)||strncasecmp(reinterpret_cast<const char*>(e.p),host,hostlen)){
     *reason="ClientHello hostname does not match this capture";return false;
    }sni=true;break;
   }
   case 10:if(!vector16(e,out->groups))return false;break;
   case 13:if(!vector16(e,out->signatures))return false;break;
   case 51:{
    if(!e.word(z)||z!=e.n)return false;
    while(e.n){uint16_t group,len;if(!e.word(group)||!e.word(len)||!len||!e.skip(len)||!add(out->shares,group))return false;}break;
   }
   case 43:{
    meshpn_profile_ids_t versions{};
    if(!e.byte(b)||b!=e.n||!ids(e,versions)||versions.count!=2||versions.values[0]!=772||versions.values[1]!=771){*reason="Unsupported advertised TLS versions";return false;}break;
   }
   case 11:
    if(e.n!=2||e.p[0]!=1||e.p[1]!=0){*reason="Unsupported EC point formats";return false;}break;
   case 16:{
    if(!e.word(z)||z!=e.n||!e.byte(b)||b!=2||e.n<2||memcmp(e.p,"h2",2)||!e.skip(2))return false;
    if(e.n){if(!e.byte(b)||b!=8||e.n!=8||memcmp(e.p,"http/1.1",8))return false;out->http1=true;}break;
   }
   case 27:
    if(e.n!=3||e.p[0]!=2||e.p[1]!=0||e.p[2]!=2){*reason="Unsupported certificate compression; only Brotli is available";return false;}break;
   case 17613:
    if(e.n!=5||memcmp(e.p,"\x00\x03\x02h2",5)){*reason="Unsupported ALPS protocols";return false;}break;
   // Other supported extensions are presence/order only. Never retain their payloads.
   default:break;
  }
 }
 if(!sni)return false;
 out->version=1;memcpy(out->ja3,hashes.ja3,sizeof(out->ja3));memcpy(out->ja4,hashes.ja4,sizeof(out->ja4));
 // Hash a zero-initialised structural model before adding human name or ID.
 uint8_t digest[32];SHA256(reinterpret_cast<const uint8_t*>(out),sizeof(*out),digest);
 static const char hex[]="0123456789abcdef";out->id[0]='c';out->id[1]='-';
 for(unsigned i=0;i<12;i++){out->id[2+2*i]=hex[digest[i]>>4];out->id[3+2*i]=hex[digest[i]&15];}
 memcpy(out->name,name,strlen(name)+1);
 if(!meshpn_profile_valid(out)){*reason="Browser uses TLS fields outside the supported profile subset";return false;}
 *reason=nullptr;return true;
}
