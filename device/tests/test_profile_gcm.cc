#include "profile_gcm.h"
#include "esp_heap_caps.h"
#include <openssl/err.h>
#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <vector>

static bool fail_alloc;
static std::unordered_map<void *, size_t> allocations;
extern "C" void *heap_caps_malloc(size_t size, int caps) {
    if ((caps & MALLOC_CAP_DMA) && std::getenv("MESHPN_TEST_DMA_ALLOC_FAIL")) return nullptr;
    if (fail_alloc) return nullptr;
    void *p=malloc(size); assert(p); allocations[p]=size; return p;
}
extern "C" void heap_caps_free(void *p) {
    const auto size=allocations.at(p);
    const auto *bytes=static_cast<const uint8_t *>(p);
    assert(std::all_of(bytes,bytes+size,[](uint8_t v){return v==0;}));
    allocations.erase(p); free(p);
}
static std::vector<uint8_t> unhex(std::string s) {
    std::vector<uint8_t> out; if(s=="-")return out;
    assert(s.size()%2==0);
    for(size_t i=0;i<s.size();i+=2)out.push_back(std::stoul(s.substr(i,2),nullptr,16));
    return out;
}
int main(int argc,char **argv) {
    assert(meshvpn_profile_gcm_self_test());
    assert(argc==2);std::ifstream input(argv[1]);assert(input);
    std::string fields[6];unsigned count=0;
    while(input>>fields[0]>>fields[1]>>fields[2]>>fields[3]>>fields[4]>>fields[5]) {
        auto key=unhex(fields[0]),nonce=unhex(fields[1]),aad=unhex(fields[2]),plain=unhex(fields[3]),cipher=unhex(fields[4]),tag=unhex(fields[5]);
        const size_t n=plain.size(); assert(cipher.size()==n&&tag.size()==16);
        // Allocate a real byte even for the empty case; pointer arithmetic on
        // an empty vector's null data is not defined.
        std::vector<uint8_t> src(std::max(n,size_t(1))),out(src.size(),0xa5),got_tag(16);
        std::copy(plain.begin(),plain.end(),src.begin());
        const size_t split=n/3,asplit=aad.size()/2;
        std::vector<uint8_t> ad(std::max(aad.size(),size_t(1)));std::copy(aad.begin(),aad.end(),ad.begin());
        CRYPTO_IOVEC data[]={{out.data(),src.data(),split},{out.data()+split,src.data()+split,n-split}};
        CRYPTO_IVEC ads[]={{ad.data(),asplit},{ad.data()+asplit,aad.size()-asplit}};
        assert(meshvpn_profile_gcm(true,key.data(),key.size(),data,nonce,ads,got_tag.data(),nullptr,16));
        assert(std::equal(cipher.begin(),cipher.end(),out.begin())&&tag==got_tag);
        src=out; std::fill(out.begin(),out.end(),0xa5);
        data[0].in=src.data();data[1].in=src.data()+split;
        assert(meshvpn_profile_gcm(false,key.data(),key.size(),data,nonce,ads,nullptr,tag.data(),16));
        assert(std::equal(plain.begin(),plain.end(),out.begin()));
        // Wrong tag, nonce, AAD and ciphertext must never publish plaintext.
        for(unsigned bad=0;bad<4;bad++) {
            auto nt=tag,nn=nonce,aa=ad,cc=src;
            if(bad==0)nt[0]^=1;
            if(bad==1)nn[0]^=1;
            if(bad==2){if(aad.empty())continue;aa[0]^=1;}
            if(bad==3){if(!n)continue;cc[0]^=1;}
            CRYPTO_IOVEC d[]={{out.data(),cc.data(),n}};
            CRYPTO_IVEC a[]={{aa.data(),aad.size()}};
            std::fill(out.begin(),out.end(),0xa5);
            assert(!meshvpn_profile_gcm(false,key.data(),key.size(),d,nn,a,nullptr,nt.data(),16));
            assert(std::all_of(out.begin(),out.end(),[](uint8_t v){return v==0xa5;}));ERR_clear_error();
        }
        // Standard EVP entrypoints exercise the patched BoringSSL implementation,
        // including its in-place and scatter/gather validation.
        EVP_AEAD_CTX ctx;EVP_AEAD_CTX_zero(&ctx);
        const EVP_AEAD *aead=key.size()==16?EVP_aead_aes_128_gcm():EVP_aead_aes_256_gcm();
        assert(EVP_AEAD_CTX_init(&ctx,aead,key.data(),key.size(),16,nullptr));
        if(nonce.size()==12){
            std::copy(plain.begin(),plain.end(),src.begin());
            CRYPTO_IOVEC inplace[]={{src.data(),src.data(),split},{src.data()+split,src.data()+split,n-split}};
            size_t tag_size=0;
            assert(EVP_AEAD_CTX_sealv(&ctx,inplace,2,got_tag.data(),&tag_size,16,nonce.data(),nonce.size(),ads,2));
            assert(tag_size==16&&got_tag==tag&&std::equal(cipher.begin(),cipher.end(),src.begin()));
            assert(EVP_AEAD_CTX_openv_detached(&ctx,inplace,2,nonce.data(),nonce.size(),tag.data(),tag.size(),ads,2));
            assert(std::equal(plain.begin(),plain.end(),src.begin()));
        }
        EVP_AEAD_CTX_cleanup(&ctx);
        fail_alloc=true;std::fill(out.begin(),out.end(),0xa5);
        assert(!meshvpn_profile_gcm(true,key.data(),key.size(),data,nonce,ads,got_tag.data(),nullptr,16));
        fail_alloc=false;assert(allocations.empty());ERR_clear_error();count++;
    }
    uint8_t key[16]={},nonce[12]={},data[16]={},out[16]={},tag[16]={};size_t tag_len;
    for (const EVP_AEAD *aead : {EVP_aead_aes_128_gcm_tls12(), EVP_aead_aes_128_gcm_tls13()}) {
        EVP_AEAD_CTX ctx;EVP_AEAD_CTX_zero(&ctx);std::memset(nonce,0,sizeof(nonce));
        assert(EVP_AEAD_CTX_init(&ctx,aead,key,16,16,nullptr));
        CRYPTO_IOVEC d{out,data,16};
        assert(EVP_AEAD_CTX_sealv(&ctx,&d,1,tag,&tag_len,16,nonce,12,nullptr,0));
        assert(!EVP_AEAD_CTX_sealv(&ctx,&d,1,tag,&tag_len,16,nonce,12,nullptr,0));ERR_clear_error();
        nonce[11]=1;assert(EVP_AEAD_CTX_sealv(&ctx,&d,1,tag,&tag_len,16,nonce,12,nullptr,0));
        EVP_AEAD_CTX_cleanup(&ctx);
    }
    CRYPTO_IOVEC too_big{out,data,18433};
    assert(!meshvpn_profile_gcm(true,key,16,{&too_big,1},nonce,{},tag,nullptr,16));ERR_clear_error();
    assert(allocations.empty()&&count>=50);
    assert((meshvpn_profile_gcm_psram_fallbacks()>0)==(std::getenv("MESHPN_TEST_DMA_ALLOC_FAIL")!=nullptr));
    std::cout<<"GCM vectors/negative/in-place/OOM/nonce tests passed: "<<count<<" vectors\n";
}
