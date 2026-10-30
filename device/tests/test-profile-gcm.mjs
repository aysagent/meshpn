import fs from 'node:fs';
import path from 'node:path';
import {createCipheriv} from 'node:crypto';
import {execFileSync} from 'node:child_process';
const [source,build,mbed]=process.argv.slice(2);
if(!mbed)throw Error('Usage: node test-profile-gcm.mjs PATCHED_BSSL_SOURCE BSSL_BUILD MBEDTLS_BUILD');
const root=new URL('../',import.meta.url).pathname;
const out=path.join(build,'gcm-test');fs.mkdirSync(out,{recursive:true});
const lines=[];
for(const keylen of [16,32])for(const ivlen of [4,12,16,64])for(const length of [0,1,15,16,17,1400,16385,18432]){
 const key=Buffer.alloc(keylen,3),iv=Buffer.alloc(ivlen,7),aad=Buffer.alloc(length%2?5:0,9),plain=Buffer.alloc(length,11);
 const cipher=createCipheriv(`aes-${keylen*8}-gcm`,key,iv);cipher.setAAD(aad);
 const encrypted=Buffer.concat([cipher.update(plain),cipher.final()]);
 lines.push([key,iv,aad,plain,encrypted,cipher.getAuthTag()].map(b=>b.toString('hex')||'-').join(' '));
}
// NIST SP800-38D AES-128 all-zero one-block vector.
lines.push('00000000000000000000000000000000 000000000000000000000000 - 00000000000000000000000000000000 0388dace60b6a392f328c2b971b2fe78 ab6e47d42cec13bdf53a67b21257bddf');
fs.writeFileSync(out+'/vectors.txt',lines.join('\n')+'\n');
fs.writeFileSync(out+'/esp_heap_caps.h',`#pragma once
#include <stddef.h>
#define MALLOC_CAP_INTERNAL 1
#define MALLOC_CAP_DMA 2
#define MALLOC_CAP_8BIT 4
extern "C" void *heap_caps_malloc(size_t,int);
extern "C" void heap_caps_free(void*);
`);
const idf=process.env.IDF_PATH||path.join(process.env.HOME,'esp/esp-idf-meshpn-v5.5.5');
execFileSync('c++',['-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+out,'-I'+source+'/include','-I'+idf+'/components/mbedtls/mbedtls/include','-I'+root+'components/meshvpn_profiled_tls/include',root+'tests/test_profile_gcm.cc',root+'components/meshvpn_profiled_tls/profile_gcm.cc',root+'experiments/profiled-tls/heap_hooks.cc',build+'/libcrypto.a',mbed+'/library/libmbedcrypto.a','-o',out+'/test'],{stdio:'inherit'});
execFileSync(out+'/test',[out+'/vectors.txt'],{stdio:'inherit'});
