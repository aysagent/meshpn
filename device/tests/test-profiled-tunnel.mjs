import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import tls from 'node:tls';
import {randomBytes} from 'node:crypto';
import {spawn,execFileSync} from 'node:child_process';
import assert from 'node:assert/strict';
import {startRealExit} from './helpers/real-exit.mjs';
import {createLabPKI} from '../scripts/create-vpn-lab-pki.mjs';
const deps=process.argv[2];if(!deps)throw Error('Pass the build-host.sh output directory');
const root=new URL('../',import.meta.url).pathname;
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-profile-tunnel-'));
const pki=await createLabPKI(path.join(dir,'pki'));
const key=randomBytes(32),secret=path.join(dir,'secret.bin'),hex=path.join(dir,'key.hex'),wrong=path.join(dir,'wrong.hex');
fs.writeFileSync(secret,key,{mode:0o600});fs.writeFileSync(hex,key.toString('hex'),{mode:0o600});fs.writeFileSync(wrong,randomBytes(32).toString('hex'),{mode:0o600});
fs.writeFileSync(dir+'/esp_heap_caps.h',`#pragma once
#include <stddef.h>
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
#ifdef __cplusplus
extern "C" {
#endif
void *heap_caps_malloc(size_t,int);
void heap_caps_free(void*);
#ifdef __cplusplus
}
#endif
`);
const common=['-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined'];
execFileSync('cc',['-std=c11',...common,'-I'+root+'components/meshvpn_vpn/include','-c',root+'components/meshvpn_vpn/meshvpn_vpn_frame.c','-o',dir+'/frame.o'],{stdio:'inherit'});
execFileSync('c++',['-std=c++17',...common,'-I'+dir,'-I'+deps+'/bssl-source/include','-I'+deps+'/brotli-source/c/include','-I'+root+'components/meshvpn_profiled_tls/include','-I'+root+'components/meshvpn_vpn/include',
 root+'tests/test_profile_tunnel.cc',...['profile_tunnel.cc','profile_client.cc','profile_gate.cc'].map(f=>root+'components/meshvpn_profiled_tls/'+f),root+'components/meshvpn_profiled_tls/profile_allocator.cc',root+'tests/profile_heap_adapter.cc',dir+'/frame.o',deps+'/bssl/libssl.a',deps+'/bssl/libcrypto.a',deps+'/brotli/libbrotlidec.a',deps+'/brotli/libbrotlicommon.a','-o',dir+'/client'],{stdio:'inherit'});
const results=[];
async function client(port,mode='success',opts={}) {
 const report=await new Promise((resolve,reject)=>{
  const c=spawn(dir+'/client',[String(port),opts.ca||pki.ca,opts.key||hex,opts.name||'exit.meshpn.test',mode],{stdio:['ignore','pipe','pipe'],env:{...process.env,...(opts.failAfter!=null?{MESHPN_TEST_ALLOC_FAIL_AFTER:String(opts.failAfter)}:{})}});let stdout='',stderr='';
  const timer=setTimeout(()=>c.kill('SIGKILL'),18000);
  c.stdout.on('data',b=>stdout+=b);c.stderr.on('data',b=>stderr+=b);c.on('error',reject);
  c.once('exit',code=>{clearTimeout(timer);try{assert.equal(code,0,stdout+stderr);const entries=stdout.trim().split('\n').map(line=>JSON.parse(line));resolve({...entries.at(-1),cycles:entries.length,heap:stderr.trim()});}catch(e){reject(e);}});
 });results.push({mode,...report});return report;
}
const peer=await startRealExit({type:'tls',tlsRaw:false,tlsLogJa3:true,tlsHttpVers:'1.1',cert:pki.certificate,key:pki.privateKey,sharedHmacKey:secret,onPacket(p,c){c.send({inject:p.toString('base64')});}});
try {
 for(let i=0;i<10;i++) { const r=await client(peer.port);assert.equal(r.ja3,'ed63604b6e93c62437468be3f6b387c3');assert.equal(r.ja4,'t13d1517h2_8daaf6152771_cb7bf5808d99'); }
 assert.equal(peer.packets.length,640);
 const repeated=await client(peer.port,'repeat');assert.equal(repeated.cycles,20);assert.equal(peer.packets.length,1920);
 await client(peer.port,'cancel');
 const before=peer.packets.length;
 const bad=await client(peer.port,'reject',{key:wrong});assert.equal(bad.phase,'auth_rejected');
 await client(peer.port,'reject',{name:'wrong.meshpn.test'});
 await client(peer.port,'reject',{ca:path.join(dir,'pki/other.pem')});
 const profile=await client(peer.port,'profile');assert.equal(profile.tls_bytes,0);
 for(const failAfter of [0,50,250])await client(peer.port,'reject',{failAfter});
 assert.equal(peer.packets.length,before);
 assert.match(peer.log(),/tls vpn: connected/);assert.match(peer.log(),/ed63604b6e93c62437468be3f6b387c3/);assert.match(peer.log(),/t13d1517h2_8daaf6152771_cb7bf5808d99/);assert.doesNotMatch(peer.log(),/bearer_legacy=1/);
 const ja3=[...peer.log().matchAll(/tls ja3 \(exit\): ja3_md5=([a-f0-9]+)/g)].map(m=>m[1]);
 const ja4=[...peer.log().matchAll(/tls ja4 \(exit\): ja4=(\S+)/g)].map(m=>m[1]);
 const hellos=results.reduce((n,r)=>n+r.hellos*r.cycles,0);
 assert.equal(ja3.length,hellos);assert.equal(ja4.length,hellos);
 for(const value of ja3)assert.equal(value,'ed63604b6e93c62437468be3f6b387c3');
 for(const value of ja4)assert.equal(value,'t13d1517h2_8daaf6152771_cb7bf5808d99');
}finally{await peer.close();}
// Real TLS peers exercise protocol rejection and cancellation without a VPS.
for(const mode of ['h2','cover','duplicate','chunked','truncated','oversize','disconnect','invalid','backpressure','slow','cancel_auth','expired','future','folded']) {
 const sockets=new Set();
 const server=tls.createServer({cert:fs.readFileSync(['expired','future'].includes(mode)?path.join(dir,'pki',mode+'.pem'):pki.certificate),key:fs.readFileSync(pki.privateKey),minVersion:'TLSv1.3',ALPNProtocols:[mode==='h2'?'h2':'http/1.1']},s=>{
  sockets.add(s);s.on('error',()=>{});s.on('close',()=>sockets.delete(s));
  let data='';s.on('data',b=>{data+=b.toString('latin1');if(!data.includes('\r\n\r\n'))return;s.removeAllListeners('data');
    if(mode==='slow'||mode==='cancel_auth')return;
    if(mode==='invalid'){s.write('HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n');s.write(Buffer.from([0x7f,0xff,0xff,0xff]));return;}
    if(mode==='backpressure'){s.write('HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n');s.pause();return;}
    if(mode==='disconnect'){s.write('HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n',()=>s.destroy());return;}
    const reply=mode==='folded'?'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n X: folded\r\n\r\n':mode==='cover'?'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nIt works!':
     mode==='duplicate'?'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Type: application/octet-stream\r\n\r\n':
     mode==='chunked'?'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n':
     mode==='oversize'?'HTTP/1.1 200 OK\r\nX: '+ 'a'.repeat(5000):'HTTP/1.1 200 OK\r\nContent-Type: applic';
    // ACK parser must also handle arbitrary TLS record boundaries.
    if(mode==='truncated')s.end(reply);else {for(let i=0;i<reply.length;i+=7)s.write(reply.slice(i,i+7));}
  });
 });server.on('tlsClientError',()=>{});await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try {const r=await client(server.address().port,['disconnect','invalid','backpressure','cancel_auth'].includes(mode)?mode:'reject');if(mode==='h2')assert.equal(r.phase,'exit_requires_http1');if(mode==='invalid')assert.equal(r.phase,'invalid_frame');if(mode==='backpressure')assert.equal(r.phase,'tx_timeout');}
 finally {for(const s of sockets)s.destroy();await new Promise(r=>server.close(r));}
}
const idle=new Set();const server=net.createServer(s=>{idle.add(s);s.on('error',()=>{});s.on('close',()=>idle.delete(s));});await new Promise(r=>server.listen(0,'127.0.0.1',r));
try {const r=await client(server.address().port,'cancel_handshake');assert.equal(r.phase,'handshake_wait');}
finally{for(const s of idle)s.destroy();await new Promise(r=>server.close(r));}
fs.writeFileSync(path.join(dir,'result.json'),JSON.stringify({scope:'Production profiled session + real JS exit, in-memory TUN; no board/NAT',results,realExitArtifacts:peer.dir},null,2));
console.log('Profiled TLS tunnel tests passed: '+dir);
