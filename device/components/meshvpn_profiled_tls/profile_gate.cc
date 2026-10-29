#include "meshvpn_profiled_tls.h"
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
// Fixed storage: parsing a hostile/mutated hello cannot grow the heap or stack.
namespace {
struct Cursor {
 const uint8_t *p; size_t n;
 bool take(size_t len,const uint8_t*&out){if(len>n)return false;out=p;p+=len;n-=len;return true;}
 bool byte(uint8_t&x){if(!n)return false;x=*p++;--n;return true;}
 bool word(uint16_t&x){if(n<2)return false;x=uint16_t(p[0])*256+p[1];p+=2;n-=2;return true;}
 bool sub(size_t len,Cursor&out){const uint8_t*at;if(!take(len,at))return false;out={at,len};return true;}
};
bool grease(uint16_t x){return (x&0x0f0f)==0x0a0a && (x>>8)==(x&255);}
struct IDs {
 std::array<uint16_t,64> values{};size_t n=0;
 bool add(uint16_t x){if(grease(x))return true;if(n==values.size())return false;values[n++]=x;return true;}
 bool read(Cursor c){if(c.n%2)return false;while(c.n){uint16_t x;if(!c.word(x)||!add(x))return false;}return true;}
 bool same(const IDs&other)const{return n==other.n&&std::equal(values.begin(),values.begin()+n,other.values.begin());}
};
struct Text {
 char data[2048]{};size_t n=0;
 bool put(const char*s){size_t z=strlen(s);if(z>=sizeof(data)-n)return false;memcpy(data+n,s,z+1);n+=z;return true;}
 bool number(uint16_t x,bool hex){char b[8];snprintf(b,sizeof(b),hex?"%04x":"%u",unsigned(x));return put(b);}
 bool ids(const IDs&v,const char*separator,bool hex){for(size_t i=0;i<v.n;i++){if(i&&!put(separator))return false;if(!number(v.values[i],hex))return false;}return true;}
};
void hex(const uint8_t*p,size_t n,char*out){static const char digits[]="0123456789abcdef";for(size_t i=0;i<n;i++){out[2*i]=digits[p[i]>>4];out[2*i+1]=digits[p[i]&15];}out[2*n]=0;}
}
extern "C" bool meshvpn_profiled_tls_check_expected(const uint8_t*hello,size_t length,const char*ja3,const char*ja4,meshvpn_profile_check_t*out){
 if(!out)return false;
 *out={};
 if(!hello||length<4||length>8192||hello[0]!=1||((size_t(hello[1])<<16)|(size_t(hello[2])<<8)|hello[3])!=length-4)return false;
 Cursor c{hello+4,length-4},v{};const uint8_t*unused;uint16_t legacy,z;uint8_t small;
 if(!c.word(legacy)||!c.take(32,unused)||!c.byte(small)||small>32||!c.take(small,unused)||!c.word(z)||!c.sub(z,v))return false;
 IDs ciphers,extensions,groups,points,sigs,versions;
 if(!z||!ciphers.read(v)||!c.byte(small)||small!=1||!c.byte(small)||small!=0||!c.word(z)||z!=c.n||!c.sub(z,v))return false;
 bool sni=false,alpn=false,has_groups=false,has_points=false,has_sigs=false,has_versions=false;
 char alpn_pair[3]="00";
 while(v.n){
  uint16_t type,len;Cursor e{};
  if(!v.word(type)||!v.word(len)||!v.sub(len,e))return false;
  if(grease(type))continue;
  for(size_t i=0;i<extensions.n;i++)if(extensions.values[i]==type)return false;
  if(!extensions.add(type))return false;
  if(type==0){
   uint16_t list,host;uint8_t kind;const uint8_t*name;
   if(!e.word(list)||list!=e.n||!e.byte(kind)||kind!=0||!e.word(host)||!host||!e.take(host,name)||e.n)return false;
   for(size_t i=0;i<host;i++)if(name[i]==0)return false;
   sni=true;
  }else if(type==10||type==13){
   if(!e.word(z)||z!=e.n)return false;
   if(type==10){has_groups=true;if(!groups.read(e))return false;}else{has_sigs=true;if(!sigs.read(e))return false;}
  }else if(type==11){
   if(!e.byte(small)||small!=e.n)return false;
   has_points=true;
   while(e.n){uint8_t p;if(!e.byte(p)||!points.add(p))return false;}
  }else if(type==43){
   if(!e.byte(small)||small!=e.n||!versions.read(e))return false;
   has_versions=true;
  }else if(type==16){
   if(!e.word(z)||z!=e.n||!z)return false;
   bool first=true;while(e.n){const uint8_t*p;if(!e.byte(small)||!small||!e.take(small,p))return false;
    if(first){alpn_pair[0]=char(p[0]);alpn_pair[1]=char(p[small-1]);first=false;}}
   alpn=true;
  }
 }
 if(!sni||!alpn||!has_groups||!has_points||!has_sigs||!has_versions)return false;
 Text text;
 if(!text.number(legacy,false)||!text.put(",")||!text.ids(ciphers,"-",false)||!text.put(",")||!text.ids(extensions,"-",false)||!text.put(",")||!text.ids(groups,"-",false)||!text.put(",")||!text.ids(points,"-",false))return false;
 uint8_t md5[16],hash[32];MD5(reinterpret_cast<const uint8_t*>(text.data),text.n,md5);hex(md5,16,out->ja3);
 // Supported profile has h2 first; reject other ALPN rather than normalize it.
 if(strcmp(alpn_pair,"h2")||legacy!=771||!versions.n||*std::max_element(versions.values.begin(),versions.values.begin()+versions.n)!=772)return false;
 std::sort(ciphers.values.begin(),ciphers.values.begin()+ciphers.n);
 text={};if(!text.ids(ciphers,",",true))return false;
 SHA256(reinterpret_cast<const uint8_t*>(text.data),text.n,hash);char cipher_hash[13];hex(hash,6,cipher_hash);
 IDs ext_hash;for(size_t i=0;i<extensions.n;i++)if(extensions.values[i]!=0&&extensions.values[i]!=16&&!ext_hash.add(extensions.values[i]))return false;
 std::sort(ext_hash.values.begin(),ext_hash.values.begin()+ext_hash.n);
 text={};if(!text.ids(ext_hash,",",true)||!text.put("_")||!text.ids(sigs,",",true))return false;
 SHA256(reinterpret_cast<const uint8_t*>(text.data),text.n,hash);char extension_hash[13];hex(hash,6,extension_hash);
 snprintf(out->ja4,sizeof(out->ja4),"t13d%02u%02uh2_%s_%s",unsigned(ciphers.n),unsigned(extensions.n),cipher_hash,extension_hash);
 out->match=ja3&&ja4&&!strcmp(out->ja3,ja3)&&!strcmp(out->ja4,ja4);
 return out->match;
}

extern "C" bool meshvpn_profiled_tls_check(const uint8_t*h,size_t n,meshvpn_profile_check_t*out){return meshvpn_profiled_tls_check_expected(h,n,"ed63604b6e93c62437468be3f6b387c3","t13d1517h2_8daaf6152771_cb7bf5808d99",out);}
