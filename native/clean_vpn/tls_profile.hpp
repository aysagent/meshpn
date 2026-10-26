#pragma once
// Opt-in, immutable cold ClientHello configuration. No captured key material,
// opaque extension replay, trust overrides or browser-wide fidelity claims.
#include "transparent_hello.hpp"
#include <nlohmann/json.hpp>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <memory>
#include <algorithm>
#include <cctype>
#include <map>
#include <tuple>

namespace cvpn::profile {
using json = nlohmann::json;
using transparent::require;
using transparent::u16;
inline bool grease(uint16_t n) { return (n & 0x0f0f) == 0x0a0a && (n >> 8) == (n & 255); }
inline void fields(const json& j, const std::set<std::string>& keys) {
  require(j.is_object() && j.size() == keys.size(), "profile_fields");
  for (const auto& k : keys) require(j.contains(k), "profile_fields");
}
inline std::vector<uint16_t> ids(const json& j, size_t max, bool empty=false) {
  require(j.is_array() && j.size() <= max && (empty || !j.empty()), "profile_list");
  std::vector<uint16_t> out; std::set<uint16_t> seen;
  for (const auto& v : j) {
    require(v.is_number_integer() && v >= 0 && v <= 65535, "profile_id");
    auto n=v.get<uint16_t>(); require(!grease(n) && seen.insert(n).second, "profile_duplicate_or_grease"); out.push_back(n);
  }
  return out;
}
inline std::string digest(const std::string& text) {
  uint8_t sum[32]; SHA256(reinterpret_cast<const uint8_t*>(text.data()), text.size(), sum);
  const char* hex="0123456789abcdef"; std::string out;
  for (auto b : sum) { out+=hex[b>>4]; out+=hex[b&15]; } return out;
}
struct Profile {
  json document;
  std::string id, sha256;
  std::vector<uint16_t> ciphers, groups, shares, signatures, extensions;
  bool optional_padding=false;
  Bytes alpn;
  bool grease_enabled, permute, ech, ocsp, sct;
  uint16_t minimum;
  explicit Profile(const json& j) : document(j) {
    fields(j,{"schema","kind","id","scenario","tls"});
    require(j.at("schema").is_number_integer() && j.at("schema")==1 &&
      j.at("kind")=="clean-vpn-native-tls-profile" && j.at("scenario")=="cold", "profile_schema");
    id=j.at("id").get<std::string>(); require(!id.empty() && id.size()<=64,"profile_id");
    for (unsigned char c : id) require(std::isalnum(c)||c=='-'||c=='_'||c=='.',"profile_id");
    const auto& t=j.at("tls");
    fields(t,{"min_version","max_version","cipher_suites","supported_groups","key_share_groups",
      "signature_algorithms","alpn","grease","permute_extensions","ech_grease","ocsp","sct","extension_types","optional_extension_types"});
    require(t.at("min_version").is_number_integer() && t.at("max_version").is_number_integer() &&
      (t.at("min_version")==771 || t.at("min_version")==772) && t.at("max_version")==772,"profile_versions");
    minimum=t.at("min_version").get<uint16_t>();
    ciphers=ids(t.at("cipher_suites"),32); groups=ids(t.at("supported_groups"),16);
    shares=ids(t.at("key_share_groups"),4,true); signatures=ids(t.at("signature_algorithms"),32);
    extensions=ids(t.at("extension_types"),32);
    auto optional=ids(t.at("optional_extension_types"),1,true);
    require(optional.empty() || optional==std::vector<uint16_t>{21},"profile_optional_extensions");
    optional_padding=!optional.empty();
    require(!optional_padding || std::find(extensions.begin(),extensions.end(),21)==extensions.end(),"profile_optional_overlap");
    require(std::find(extensions.begin(),extensions.end(),0)!=extensions.end(),"profile_sni_required");
    // No PSK/early_data/raw extras. The stack must implement every advertised extension.
    for (auto n:extensions) require(n!=41 && n!=42 && n!=50 && n!=27 && n!=17513 && n!=17613,"profile_extension_unsupported");
    for (auto key:{"grease","permute_extensions","ech_grease","ocsp","sct"}) require(t.at(key).is_boolean(),"profile_boolean");
    grease_enabled=t.at("grease"); permute=t.at("permute_extensions"); ech=t.at("ech_grease"); ocsp=t.at("ocsp"); sct=t.at("sct");
    require(t.at("alpn")==json::array({"h2"}) || t.at("alpn")==json::array({"h2","http/1.1"}),"profile_alpn");
    for (const auto& p:t.at("alpn")) { auto s=p.get<std::string>(); alpn.push_back(s.size()); alpn.insert(alpn.end(),s.begin(),s.end()); }
    sha256=digest(j.dump());
  }
  void context(SSL_CTX* ctx) const {
    require(SSL_CTX_set_min_proto_version(ctx,minimum)==1 && SSL_CTX_set_max_proto_version(ctx,TLS1_3_VERSION)==1,"profile_versions");
    std::vector<uint16_t> tls13; std::string tls12; bool old=false;
    for (auto id:ciphers) {
      const auto* c=SSL_get_cipher_by_value(id); require(c!=nullptr,"profile_cipher_unsupported");
      if (SSL_CIPHER_get_min_version(c)==TLS1_3_VERSION) {
        require(!old,"profile_cipher_order"); tls13.push_back(id);
      } else {
        require(minimum==TLS1_2_VERSION && SSL_CIPHER_get_max_version(c)>=TLS1_2_VERSION,"profile_cipher_unsupported");
        // Profiles cannot enable static-RSA, CBC or obsolete bulk ciphers.
        require(std::set<uint16_t>{49195,49196,49199,49200,52392,52393}.count(id),"profile_cipher_policy");
        old=true; if (!tls12.empty()) tls12+=':'; tls12+=SSL_CIPHER_get_name(c);
      }
    }
    require(!tls13.empty() && (minimum==TLS1_3_VERSION || !tls12.empty()),"profile_cipher_versions");
    require(SSL_CTX_set_tls13_client_cipher_order(ctx,tls13.data(),tls13.size())==1,"profile_ciphers");
    if (!tls12.empty()) require(SSL_CTX_set_strict_cipher_list(ctx,tls12.c_str())==1,"profile_ciphers");
    require(SSL_CTX_set1_group_ids(ctx,groups.data(),groups.size())==1,"profile_groups");
    for(auto s:signatures)require(std::set<uint16_t>{0x0401,0x0501,0x0601,0x0403,0x0503,0x0603,0x0804,0x0805,0x0806,0x0807}.count(s),"profile_signature_policy");
    require(SSL_CTX_set_verify_algorithm_prefs(ctx,signatures.data(),signatures.size())==1,"profile_signatures");
    require(SSL_CTX_set_alpn_protos(ctx,alpn.data(),alpn.size())==0,"profile_alpn");
    SSL_CTX_set_grease_enabled(ctx,grease_enabled); SSL_CTX_set_permute_extensions(ctx,permute);
    if(ocsp) SSL_CTX_enable_ocsp_stapling(ctx);
    if(sct) SSL_CTX_enable_signed_cert_timestamps(ctx);
  }
  void connection(SSL* ssl) const {
    require(SSL_set1_client_key_shares(ssl,shares.data(),shares.size())==1,"profile_key_shares");
    SSL_set_enable_ech_grease(ssl,ech);
  }
  // Check the SAME generated ClientHello that will be sent, before any TLS byte
  // reaches the socket. Full native extension semantics remain in BoringSSL.
  void verify(const Bytes& wire) const {
    const auto h=transparent::parse(wire); const auto& p=h.payload;
    size_t at=39+p[38]; auto n=u16(p,at); at+=2;
    auto vector=[&](size_t start,size_t size) {
      require(!(size&1) && start<=p.size() && size<=p.size()-start,"profile_wire_length");
      std::vector<uint16_t> out; for(size_t k=start;k<start+size;k+=2) { auto v=u16(p,k); if(!grease(v))out.push_back(v); } return out;
    };
    require(vector(at,n)==ciphers,"profile_wire_ciphers");
    bool cipher_grease=false; for(size_t k=at;k<at+n;k+=2)cipher_grease|=grease(u16(p,k));
    require(cipher_grease==grease_enabled,"profile_wire_grease");
    std::map<uint16_t,std::pair<size_t,size_t>> ex; std::vector<uint16_t> order;
    for(at=h.extensions_at+2;at<p.size();) {
      const auto type=u16(p,at); n=u16(p,at+2);at+=4;
      if(!grease(type)){ex[type]={at,n};order.push_back(type);} at+=n;
    }
    auto wanted=extensions, actual=order;
    if(ex.count(21))require(order.back()==21,"profile_wire_padding_order");
    if(optional_padding)actual.erase(std::remove(actual.begin(),actual.end(),21),actual.end());
    if(permute){std::sort(wanted.begin(),wanted.end());std::sort(actual.begin(),actual.end());}
    require(wanted==actual,"profile_wire_extensions");
    auto ext=[&](uint16_t type) { require(ex.count(type),"profile_wire_missing_extension");return ex.at(type); };
    for(const auto& pair:std::vector<std::pair<uint16_t,std::vector<uint16_t>>>{{10,groups},{13,signatures}}) {
      auto [o,len]=ext(pair.first);require(len>=2 && u16(p,o)==len-2 && vector(o+2,len-2)==pair.second,"profile_wire_vector");
    }
    auto [o,len]=ext(43);require(len>=1 && p[o]==len-1,"profile_wire_versions");
    require(vector(o+1,len-1)==(minimum==771?std::vector<uint16_t>{772,771}:std::vector<uint16_t>{772}),"profile_wire_versions");
    std::tie(o,len)=ext(16);require(len==alpn.size()+2 && u16(p,o)==alpn.size() &&
      std::equal(alpn.begin(),alpn.end(),p.begin()+o+2),"profile_wire_alpn");
    std::tie(o,len)=ext(51);require(len>=2 && u16(p,o)==len-2,"profile_wire_shares");
    std::vector<uint16_t> got;size_t end=o+len;
    for(o+=2;o<end;) {require(end-o>=4,"profile_wire_shares");auto g=u16(p,o),size=u16(p,o+2);o+=4;require(size<=end-o,"profile_wire_shares");if(!grease(g))got.push_back(g);o+=size;}
    require(got==shares,"profile_wire_shares");
  }
  Bytes first_flight(SSL* ssl) const {
    connection(ssl);
    BIO* input=BIO_new(BIO_s_mem()); BIO* output=BIO_new(BIO_s_mem());
    if(!input||!output){BIO_free(input);BIO_free(output);throw std::runtime_error("profile_bio");}
    BIO_set_mem_eof_return(input,-1); SSL_set_bio(ssl,input,output);
    int rc=SSL_do_handshake(ssl);require(rc<0 && SSL_get_error(ssl,rc)==SSL_ERROR_WANT_READ,"profile_first_flight");
    const auto size=BIO_ctrl_pending(output);require(size>0 && size<=transparent::hello_limit,"profile_hello_limit");
    Bytes bytes(size);require(BIO_read(output,bytes.data(),bytes.size())==int(bytes.size()),"profile_bio_read");
    verify(bytes); return bytes;
  }
  json report() const {
    return {{"id",id},{"sha256",sha256},{"scenario","cold"},{"tls",document.at("tls")},
      {"boringssl_revision","a7481f34712bc056a47ab91015536166b3a6cebb"},
      {"verification","generated-first-ClientHello-before-wire"},
      {"limitations",{"not-full-browser-profile","no-HTTP2-or-HTTP-mimicry","no-resumption-or-0RTT","HRR-layout-not-profile-verified","no-certificate-compression-or-ALPS"}}};
  }
};
} // namespace cvpn::profile
