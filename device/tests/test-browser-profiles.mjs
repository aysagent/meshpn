import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {measureTlsClientHello} from '../../scripts/lib/native-tls-profile-observer.mjs';
import {deviceProfile} from '../scripts/browser-profile-capture.mjs';
const deps=process.argv[2],capture=process.argv[3];if(!deps||!capture)throw Error('Pass BoringSSL host deps and capture result.json');
const root=new URL('../',import.meta.url).pathname,dir=fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-browser-profile-'));
const json=path.join(process.env.IDF_PATH||path.join(os.homedir(),'esp/esp-idf-meshpn-v5.5.5'),'components/json/cJSON');
const inc=root+'components/meshvpn_profiled_tls/include',flags=['-g','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-fsanitize=address,undefined'];
for(const [file,name] of [[root+'components/meshvpn_profiled_tls/profile_model.c','model'],[json+'/cJSON.c','json']])execFileSync('cc',['-std=c11',...flags,'-I'+inc,'-I'+json,'-c',file,'-o',dir+'/'+name+'.o'],{stdio:'inherit'});
execFileSync('c++',['-std=c++17',...flags,'-I'+inc,'-I'+json,'-I'+deps+'/bssl-source/include','-I'+deps+'/brotli-source/c/include',root+'tests/test_browser_profile.cc',root+'experiments/profiled-tls/heap_hooks.cc',root+'components/meshvpn_profiled_tls/profile_client.cc',root+'components/meshvpn_profiled_tls/profile_gate.cc',dir+'/model.o',dir+'/json.o',deps+'/bssl/libssl.a',deps+'/bssl/libcrypto.a',deps+'/brotli/libbrotlidec.a',deps+'/brotli/libbrotlicommon.a','-o',dir+'/check'],{stdio:'inherit'});
const {profiles,version}=JSON.parse(fs.readFileSync(capture));assert(profiles.length>=3);
const reports=[];
const run=(p,mode)=>{fs.writeFileSync(dir+'/input.json',typeof p==='string'?p:JSON.stringify(p));return execFileSync(dir+'/check',[dir+'/input.json',...(mode?[mode]:[])],{maxBuffer:65536});};
for(const p of profiles){
 for(let i=0;i<3;i++){
  const wire=run(p),m=measureTlsClientHello(wire);assert.equal(m.ja3,p.ja3);assert.equal(m.ja4.fingerprint,p.ja4);
  const converted=deviceProfile(wire,p.name);assert.equal(converted.status,'candidate');assert.deepEqual(converted.profile,p);
 }
 reports.push({id:p.id,ja3:p.ja3,ja4:p.ja4});
 const wrong=structuredClone(p);wrong.ja3='0'.repeat(32);run(wrong,'mismatch');
 const wrong4=structuredClone(p);wrong4.ja4=p.ja4.slice(0,24)+'0'.repeat(12);run(wrong4,'mismatch');
 const changed=structuredClone(p);[changed.tls.extension_types[0],changed.tls.extension_types[1]]=[changed.tls.extension_types[1],changed.tls.extension_types[0]];run(changed,'mismatch');
}
const p=profiles[0];
for(const modify of [p=>p.schema=2,p=>p.id='../x',p=>p.name='',p=>p.name='a'.repeat(65),p=>p.secret='x',p=>p.tls.key='x',p=>p.ja3='G'.repeat(32),p=>p.tls.cipher_suites.push(p.tls.cipher_suites[0]),p=>p.tls.cipher_suites[0]=1.5,p=>p.tls.supported_groups=[],p=>p.tls.extension_types.push(9999),p=>p.tls.certificate_compression=[1,2],p=>p.tls.alpn=['h3'],p=>p.tls.application_settings=['http/1.1'],p=>p.tls.supported_versions=[772],p=>p.tls.key_share_groups=[65535],p=>p.tls.grease=1]){
 const bad=structuredClone(p);modify(bad);run(bad,'reject');
}
run(JSON.stringify(p).replace('"schema":1','"schema":1,"schema":1'),'reject');
for(const bad of ['['.repeat(9)+']'.repeat(9),'{}\0',JSON.stringify(p).replace(p.name,'test\\u0000hidden')])run(bad,'text-reject');
fs.writeFileSync(dir+'/result.json',JSON.stringify({version,profiles:reports,repeatedPreviews:profiles.length*3,negativeCases:30},null,2));
console.log('Browser capture → bounded parser → production ClientHello → independent JA3/JA4 passed: '+dir);
