import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {measureTlsClientHello} from '../../scripts/lib/native-tls-profile-observer.mjs';
const deps=process.argv[2];if(!deps)throw Error('Pass BoringSSL host deps [real-browser hello.bin]');
const root=new URL('../',import.meta.url).pathname,dir=fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-local-capture-'));
const json=path.join(process.env.IDF_PATH||path.join(os.homedir(),'esp/esp-idf-meshpn-v5.5.5'),'components/json/cJSON');
const inc=root+'components/meshvpn_profiled_tls/include',flags=['-g','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-fsanitize=address,undefined'];
const objects=[];
for(const [file,name] of [[root+'components/meshvpn_profiled_tls/profile_model.c','model'],[root+'components/meshvpn_profiled_tls/profile_capture_wire.c','wire'],[json+'/cJSON.c','json']]){
 const obj=dir+'/'+name+'.o';objects.push(obj);execFileSync('cc',['-std=c11',...flags,'-I'+inc,'-I'+json,'-c',file,'-o',obj],{stdio:'inherit'});
}
for(const [main,name]of [['test_browser_profile.cc','generate'],['test_local_capture.cc','capture']])execFileSync('c++',['-std=c++17',...flags,'-I'+inc,'-I'+json,'-I'+deps+'/bssl-source/include','-I'+deps+'/brotli-source/c/include',root+'tests/'+main,root+'experiments/profiled-tls/heap_hooks.cc',...['profile_client.cc','profile_gate.cc','profile_capture.cc'].map(f=>root+'components/meshvpn_profiled_tls/'+f),...objects,deps+'/bssl/libssl.a',deps+'/bssl/libcrypto.a',deps+'/brotli/libbrotlidec.a',deps+'/brotli/libbrotlicommon.a','-o',dir+'/'+name],{stdio:'inherit'});
const fixture=JSON.parse(fs.readFileSync(root+'tests/fixtures/browser-profile-capture-chromium156.json'));
const inputs=[];
for(const p of fixture.profiles){fs.writeFileSync(dir+'/input.json',JSON.stringify(p));inputs.push([execFileSync(dir+'/generate',[dir+'/input.json']),'exit.meshpn.test']);}
if(process.argv[3])inputs.push([fs.readFileSync(process.argv[3]),'dongle.local']);
for(const [wire,host]of inputs){
 fs.writeFileSync(dir+'/hello.bin',wire);
 const generated=execFileSync(dir+'/capture',[dir+'/hello.bin',host]);
 const a=measureTlsClientHello(wire),b=measureTlsClientHello(generated);
 assert.equal(b.ja3,a.ja3);assert.equal(b.ja4.fingerprint,a.ja4.fingerprint);
}
console.log('Local capture → production parser → preview → independent fingerprints passed: '+inputs.length+' profiles; '+dir);
