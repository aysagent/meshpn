// Offline test credentials only. Temporary RSA CA signs an ML-DSA leaf, so the
// integration test exercises actual TLS CertificateVerify, not just a CH list.
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <stdexcept>
static void need(bool b){if(!b)throw std::runtime_error("credential_fixture_failed");}
static bssl::UniquePtr<BIO> output(const char* path) {
  int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);need(fd>=0);
  bssl::UniquePtr<BIO> bio(BIO_new_fd(fd,BIO_CLOSE));if(!bio){close(fd);need(false);}return bio;
}
int main(int argc,char** argv) {
  try {
    if(argc!=6)return 2;
    const int type=!std::strcmp(argv[3],"44")?EVP_PKEY_ML_DSA_44:
      !std::strcmp(argv[3],"65")?EVP_PKEY_ML_DSA_65:!std::strcmp(argv[3],"87")?EVP_PKEY_ML_DSA_87:0;
    need(type!=0);
    bssl::UniquePtr<BIO> ca_file(BIO_new_file(argv[1],"r")),key_file(BIO_new_file(argv[2],"r"));need(ca_file&&key_file);
    bssl::UniquePtr<X509> ca(PEM_read_bio_X509(ca_file.get(),nullptr,nullptr,nullptr));
    bssl::UniquePtr<EVP_PKEY> signer(PEM_read_bio_PrivateKey(key_file.get(),nullptr,nullptr,nullptr));need(ca&&signer);
    need(EVP_PKEY_id(signer.get())==EVP_PKEY_RSA&&X509_check_private_key(ca.get(),signer.get())==1);
    bssl::UniquePtr<EVP_PKEY_CTX> gen(EVP_PKEY_CTX_new_id(type,nullptr));need(bool(gen));need(EVP_PKEY_keygen_init(gen.get())==1);
    EVP_PKEY* raw=nullptr;need(EVP_PKEY_keygen(gen.get(),&raw)==1);bssl::UniquePtr<EVP_PKEY> key(raw);
    bssl::UniquePtr<X509> cert(X509_new());need(bool(cert));
    need(X509_set_version(cert.get(),2)==1&&ASN1_INTEGER_set(X509_get_serialNumber(cert.get()),type)==1);
    need(X509_gmtime_adj(X509_getm_notBefore(cert.get()),-60)&&X509_gmtime_adj(X509_getm_notAfter(cert.get()),172800));
    need(X509_set_issuer_name(cert.get(),X509_get_subject_name(ca.get()))==1&&X509_set_pubkey(cert.get(),key.get())==1);
    need(X509_NAME_add_entry_by_txt(X509_get_subject_name(cert.get()),"CN",MBSTRING_ASC,
      reinterpret_cast<const uint8_t*>("localhost"),-1,-1,0)==1);
    const auto extension=[&](int nid,const char* value) {
      bssl::UniquePtr<X509_EXTENSION> e(X509V3_EXT_nconf_nid(nullptr,nullptr,nid,value));
      need(e&&X509_add_ext(cert.get(),e.get(),-1)==1);
    };
    extension(NID_basic_constraints,"critical,CA:FALSE");extension(NID_key_usage,"critical,digitalSignature");
    extension(NID_ext_key_usage,"serverAuth");extension(NID_subject_alt_name,"DNS:localhost");
    need(X509_sign(cert.get(),signer.get(),EVP_sha256())>0&&X509_verify(cert.get(),signer.get())==1);
    auto cert_out=output(argv[4]),key_out=output(argv[5]);
    need(PEM_write_bio_X509(cert_out.get(),cert.get())==1);
    need(PEM_write_bio_PrivateKey(key_out.get(),key.get(),nullptr,nullptr,0,nullptr,nullptr)==1);
    need(BIO_flush(cert_out.get())==1&&BIO_flush(key_out.get())==1);
    return 0;
  }catch(const std::exception& e){std::fprintf(stderr,"%s\n",e.what());return 1;}
}
