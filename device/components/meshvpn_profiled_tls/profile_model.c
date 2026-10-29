#include "profile_model.h"
#include "cJSON.h"
#include <string.h>
#include <math.h>
static bool fields(const cJSON *j, const char *const *names, size_t n) {
 if (!cJSON_IsObject(j)) return false;
 for(const cJSON *v=j->child;v;v=v->next) {
  size_t k=0; for(;k<n;k++) if(!strcmp(v->string,names[k])) break;
  if(k==n) return false;
  for(const cJSON *w=v->next;w;w=w->next) if(!strcmp(v->string,w->string)) return false;
 }
 return true;
}
static bool str(const cJSON*j,const char*k,char*out,size_t n) {
 const cJSON*v=cJSON_GetObjectItemCaseSensitive(j,k);
 if(!cJSON_IsString(v)||!v->valuestring||!strlen(v->valuestring)||strlen(v->valuestring)>=n)return false;
 for(const unsigned char*s=(const unsigned char*)v->valuestring;*s;s++)if(*s<32||*s==127)return false;
 strcpy(out,v->valuestring);return true;
}
static bool ids(const cJSON*j,const char*k,meshpn_profile_ids_t*out) {
 const cJSON*a=cJSON_GetObjectItemCaseSensitive(j,k);int n=cJSON_GetArraySize(a);
 if(!cJSON_IsArray(a)||n<1||n>32)return false;
 out->count=n;
 for(int i=0;i<n;i++){const cJSON*v=cJSON_GetArrayItem(a,i);
  if(!cJSON_IsNumber(v)||!isfinite(v->valuedouble)||v->valuedouble<0||v->valuedouble>65535||v->valuedouble!=(uint16_t)v->valuedouble)return false;
  out->values[i]=(uint16_t)v->valuedouble;
 }
 return true;
}
static bool list_valid(const meshpn_profile_ids_t*a) {
 if(!a->count||a->count>32)return false;
 for(unsigned i=0;i<a->count;i++){
  unsigned v=a->values[i];if((v&0x0f0f)==0x0a0a&&(v>>8)==(v&255))return false;
  for(unsigned j=0;j<i;j++)if(a->values[j]==v)return false;
 }return true;
}
static bool has(const meshpn_profile_ids_t*a,unsigned v){for(unsigned i=0;i<a->count;i++)if(a->values[i]==v)return true;return false;}
static bool hex(const char*s,size_t n){if(strlen(s)!=n)return false;for(size_t i=0;i<n;i++)if(!strchr("0123456789abcdef",s[i]))return false;return true;}
bool meshpn_profile_valid(const meshpn_tls_profile_t*p){
 if(!p||p->version!=1||!memchr(p->id,0,sizeof(p->id))||!memchr(p->name,0,sizeof(p->name))||!memchr(p->ja3,0,sizeof(p->ja3))||!memchr(p->ja4,0,sizeof(p->ja4)))return false;
 if(!*p->id||!*p->name||!hex(p->ja3,32)||strlen(p->ja4)!=36||strncmp(p->ja4,"t13d",4)||strncmp(p->ja4+8,"h2_",3)||p->ja4[23]!='_'||strspn(p->ja4+24,"0123456789abcdef")!=12)return false;
 for(const char*s=p->id;*s;s++)if(!strchr("abcdefghijklmnopqrstuvwxyz0123456789-_",*s))return false;
 for(int i=4;i<8;i++)if(p->ja4[i]<'0'||p->ja4[i]>'9')return false;
 for(int i=11;i<23;i++)if(!strchr("0123456789abcdef",p->ja4[i]))return false;
 if(!list_valid(&p->ciphers)||!list_valid(&p->groups)||!list_valid(&p->shares)||p->shares.count>4||!list_valid(&p->signatures)||!list_valid(&p->extensions))return false;
 for(unsigned i=0;i<p->shares.count;i++)if(!has(&p->groups,p->shares.values[i]))return false;
 static const uint16_t allowed[]={0,5,10,11,13,16,18,21,23,27,35,43,45,51,65281,17613,65037,51764};
 for(unsigned i=0;i<p->extensions.count;i++){unsigned j=0;for(;j<sizeof(allowed)/sizeof(*allowed);j++)if(allowed[j]==p->extensions.values[i])break;if(j==sizeof(allowed)/sizeof(*allowed))return false;}
 static const uint16_t required[]={0,10,11,13,16,43,45,51};
 for(unsigned i=0;i<sizeof(required)/sizeof(*required);i++)if(!has(&p->extensions,required[i]))return false;
 return true;
}
bool meshpn_profile_parse(const cJSON*j,meshpn_tls_profile_t*p){
 if(!p)return false;
 memset(p,0,sizeof(*p));
 static const char*const root[]={"schema","id","name","ja3","ja4","tls"};
 static const char*const tls[]={"cipher_suites","supported_groups","key_share_groups","signature_algorithms","extension_types","grease","alpn","supported_versions","ec_point_formats","certificate_compression","application_settings"};
 const cJSON*t=cJSON_GetObjectItemCaseSensitive(j,"tls"),*v=cJSON_GetObjectItemCaseSensitive(j,"schema");
 if(!fields(j,root,6)||!fields(t,tls,11)||!cJSON_IsNumber(v)||v->valuedouble!=1)return false;
 p->version=1;
 if(!str(j,"id",p->id,sizeof(p->id))||!str(j,"name",p->name,sizeof(p->name))||!str(j,"ja3",p->ja3,sizeof(p->ja3))||!str(j,"ja4",p->ja4,sizeof(p->ja4))||!ids(t,"cipher_suites",&p->ciphers)||!ids(t,"supported_groups",&p->groups)||!ids(t,"key_share_groups",&p->shares)||!ids(t,"signature_algorithms",&p->signatures)||!ids(t,"extension_types",&p->extensions))return false;
 v=cJSON_GetObjectItemCaseSensitive(t,"grease");if(!cJSON_IsBool(v))return false;p->grease=cJSON_IsTrue(v);
 v=cJSON_GetObjectItemCaseSensitive(t,"alpn");int n=cJSON_GetArraySize(v);
 if(!cJSON_IsArray(v)||(n!=1&&n!=2)||!cJSON_IsString(cJSON_GetArrayItem(v,0))||strcmp(cJSON_GetArrayItem(v,0)->valuestring,"h2"))return false;
 if(n==2&&(!cJSON_IsString(cJSON_GetArrayItem(v,1))||strcmp(cJSON_GetArrayItem(v,1)->valuestring,"http/1.1")))return false;
 p->http1=n==2;
 meshpn_profile_ids_t a={0};
 if(!ids(t,"supported_versions",&a)||a.count!=2||a.values[0]!=772||a.values[1]!=771)return false;
 if(!ids(t,"ec_point_formats",&a)||a.count!=1||a.values[0]!=0)return false;
 v=cJSON_GetObjectItemCaseSensitive(t,"certificate_compression");n=cJSON_GetArraySize(v);
 if(!cJSON_IsArray(v)||n!=(has(&p->extensions,27)?1:0)||(n&&(!cJSON_IsNumber(cJSON_GetArrayItem(v,0))||cJSON_GetArrayItem(v,0)->valuedouble!=2)))return false;
 v=cJSON_GetObjectItemCaseSensitive(t,"application_settings");n=cJSON_GetArraySize(v);
 if(!cJSON_IsArray(v)||n!=(has(&p->extensions,17613)?1:0)||(n&&(!cJSON_IsString(cJSON_GetArrayItem(v,0))||strcmp(cJSON_GetArrayItem(v,0)->valuestring,"h2"))))return false;
 return meshpn_profile_valid(p);
}

/* Bound cJSON recursion before parsing untrusted import text on the HTTP stack.
 * Reject escaped NUL too: cJSON strings otherwise hide a trailing suffix. */
bool meshpn_profile_json_text_safe(const char *text,size_t length){
 if(!text||!length||length>MESHPN_PROFILE_JSON_MAX)return false;
 unsigned depth=0;bool quoted=false,escaped=false;
 for(size_t i=0;i<length;i++){
  unsigned char c=text[i];if(!c)return false;
  if(quoted){
   if(escaped){if(c=='u'&&i+4<length&&!memcmp(text+i+1,"0000",4))return false;escaped=false;}
   else if(c==92)escaped=true;
   else if(c=='"')quoted=false;
   continue;
  }
  if(c=='"')quoted=true;
  else if(c=='{'||c=='['){if(++depth>8)return false;}
  else if(c=='}'||c==']'){if(!depth)return false;depth--;}
 }
 return !quoted&&!depth;
}
