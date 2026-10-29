#include "profile_capture.h"
int meshpn_hello_capture_feed(meshpn_hello_capture_t*s,const uint8_t*b,size_t n){
 if(!s||(!b&&n)||s->failed)return -1;
 if(s->expected&&s->length==s->expected)return 1;
 while(n--){
  uint8_t c=*b++;
  if(++s->wire_bytes>16384)goto bad;
  if(s->header_length<5){
   s->header[s->header_length++]=c;
   if(s->header_length==5){
    s->remaining=((unsigned)s->header[3]<<8)|s->header[4];
    if(s->header[0]!=22||s->header[1]!=3||s->header[2]>3||!s->remaining||s->remaining>16384||++s->records>16)goto bad;
   }
   continue;
  }
  if(s->length>=sizeof(s->hello))goto bad;
  s->hello[s->length++]=c;
  if(s->length==4){
   s->expected=4+((size_t)s->hello[1]<<16)+((size_t)s->hello[2]<<8)+s->hello[3];
   if(s->hello[0]!=1||s->expected<42||s->expected>sizeof(s->hello))goto bad;
  }
  if(s->expected&&s->length==s->expected)return 1;
  if(!--s->remaining)s->header_length=0;
 }
 return 0;
bad:s->failed=true;return -1;
}
