#!/usr/bin/env python3
"""Copy pinned, already-patched clean-vpn BoringSSL; never mutate its build tree."""
import pathlib,shutil,subprocess,sys,json,hashlib
src,dst=map(pathlib.Path,sys.argv[1:])
pin='a7481f34712bc056a47ab91015536166b3a6cebb'
if subprocess.check_output(['git','-C',str(src),'rev-parse','HEAD'],text=True).strip()!=pin:
    raise SystemExit('Unexpected BoringSSL revision')
if dst.exists(): raise SystemExit('Destination must not exist')
# The six clean-vpn patches are required; reject an unpatched upstream checkout.
h=(src/'include/openssl/ssl.h').read_text()
for marker in ['SSL_CTX_set_tls13_client_cipher_order','SSL_CTX_set_meshvpn_client_signature_algorithms_cert','SSL_CTX_meshvpn_add_client_hello_extension','SSL_CTX_set_meshvpn_tls12_client_cipher_wire_order','SSL_CTX_set_meshvpn_signature_algorithms_clienthello_wire']:
    if marker not in h: raise SystemExit('Missing clean-vpn patch: '+marker)
if 'meshvpn_clienthello_extensions_contains_type' not in (src/'ssl/extensions.cc').read_text(): raise SystemExit('Missing extension dedup patch')
shutil.copytree(src,dst,ignore=shutil.ignore_patterns('.git'))
p=dst/'include/openssl/target.h';s=p.read_text()
needle='#elif defined(__riscv) && __SIZEOF_POINTER__ == 8'
if s.count(needle)!=1: raise SystemExit('Target patch context changed')
s=s.replace(needle,'#elif defined(__XTENSA__) && __SIZEOF_POINTER__ == 4\n#define OPENSSL_32_BIT\n'+needle)
p.write_text(s)
p=dst/'ssl/extensions.cc';s=p.read_text()
needle='unsigned ext_index;'
if s.count(needle)!=2: raise SystemExit('Extension index patch context changed')
p.write_text(s.replace(needle,'uint32_t ext_index;'))
# Explicit allocator hooks only in the host measurement build. Mach-O does not
# enter upstream's ELF weak-symbol branch; do not report an inactive hook as zero.
p=dst/'crypto/mem.cc';s=p.read_text()
needle='WEAK_SYMBOL_FUNC(void *, OPENSSL_memory_alloc, (size_t size))\nWEAK_SYMBOL_FUNC(void, OPENSSL_memory_free, (void *ptr))\nWEAK_SYMBOL_FUNC(size_t, OPENSSL_memory_get_size, (void *ptr))'
if s.count(needle)!=1: raise SystemExit('Allocator patch context changed')
p.write_text(s.replace(needle,'#if defined(MESHPN_PROBE_ALLOCATOR)\nextern "C" {\nvoid *OPENSSL_memory_alloc(size_t);\nvoid OPENSSL_memory_free(void *);\nsize_t OPENSSL_memory_get_size(void *);\n}\n#else\n'+needle+'\n#endif'))
p=dst/'crypto/mem.cc';s=p.read_text()
for name in ['OPENSSL_memory_alloc','OPENSSL_memory_free','OPENSSL_memory_get_size']:
    s=s.replace('if ('+name+' != nullptr)', '#if defined(MESHPN_PROBE_ALLOCATOR)\n  if (true)\n#else\n  if ('+name+' != nullptr)\n#endif\n')
p.write_text(s)
manifest={'upstream_commit':pin,'input_diff_sha256':hashlib.sha256(subprocess.check_output(['git','-C',str(src),'diff','--no-ext-diff','HEAD'])).hexdigest(),
 'probe_changes':['Xtensa little-endian 32-bit target','uint32_t extension indices','optional explicit host allocator hooks'],
 'port_files_sha256':{str(p.relative_to(dst)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [dst/'include/openssl/target.h',dst/'ssl/extensions.cc',dst/'crypto/mem.cc']}}
(dst/'meshpn-probe-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(dst)
