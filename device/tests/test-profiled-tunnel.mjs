import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import tls from 'node:tls';
import http2 from 'node:http2';
import {randomBytes} from 'node:crypto';
import {spawn,execFileSync} from 'node:child_process';
import assert from 'node:assert/strict';
import {startRealExit} from './helpers/real-exit.mjs';
import {createLabPKI} from '../scripts/create-vpn-lab-pki.mjs';
const deps=process.argv[2];if(!deps)throw Error('Pass the build-host.sh output directory');
const root=new URL('../',import.meta.url).pathname;
const h2source=path.resolve(deps,'nghttp2-source'),h2build=path.resolve(deps,'nghttp2');
if(!fs.existsSync(h2source))execFileSync('bash',[root+'experiments/profiled-tls/prepare-nghttp2.sh',h2source],{stdio:'inherit'});
execFileSync('cmake',['-S',root+'experiments/profiled-tls/nghttp2-host','-B',h2build],{env:{...process.env,MESHPN_PROBE_NGHTTP2_SOURCE:h2source},stdio:'pipe'});
execFileSync('cmake',['--build',h2build,'-j','4'],{stdio:'pipe'});
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
const json=path.join(os.homedir(),'esp/esp-idf-meshpn-v5.5.5/components/json/cJSON');
for(const [file,name] of [[root+'components/meshvpn_profiled_tls/profile_model.c','model'],[json+'/cJSON.c','json']])execFileSync('cc',['-std=c11',...common,'-Wno-deprecated-declarations','-I'+root+'components/meshvpn_profiled_tls/include','-I'+json,'-c',file,'-o',dir+'/'+name+'.o'],{stdio:'inherit'});
execFileSync('c++',['-std=c++17',...common,'-I'+json,'-I'+h2source+'/lib/includes','-I'+dir,'-I'+deps+'/bssl-source/include','-I'+deps+'/brotli-source/c/include','-I'+root+'components/meshvpn_profiled_tls/include','-I'+root+'components/meshvpn_vpn/include',
 root+'tests/test_profile_tunnel.cc',...['profile_tunnel.cc','profile_client.cc','profile_gate.cc'].map(f=>root+'components/meshvpn_profiled_tls/'+f),root+'components/meshvpn_profiled_tls/profile_allocator.cc',root+'tests/profile_heap_adapter.cc',dir+'/frame.o',dir+'/model.o',dir+'/json.o',deps+'/bssl/libssl.a',deps+'/bssl/libcrypto.a',deps+'/brotli/libbrotlidec.a',deps+'/brotli/libbrotlicommon.a',h2build+'/libmeshpn_nghttp2.a','-o',dir+'/client'],{stdio:'inherit'});
execFileSync('cc',['-std=c11',...common,'-I'+h2source+'/lib/includes','-I'+root+'components/meshvpn_profiled_tls',root+'tests/test_profile_alps.c',h2build+'/libmeshpn_nghttp2.a','-o',dir+'/test-alps'],{stdio:'inherit'});
execFileSync(dir+'/test-alps',[],{stdio:'inherit'});
const results=[];
async function client(port,mode='success',opts={}) {
 const report=await new Promise((resolve,reject)=>{
  const c=spawn(dir+'/client',[String(port),opts.ca||pki.ca,opts.key||hex,opts.name||'exit.meshpn.test',mode],{stdio:['ignore','pipe','pipe'],env:{...process.env,...(opts.failAfter!=null?{MESHPN_TEST_ALLOC_FAIL_AFTER:String(opts.failAfter)}:{})}});let stdout='',stderr='';
  const timer=setTimeout(()=>c.kill('SIGKILL'),18000);
  c.stdout.on('data',b=>stdout+=b);c.stderr.on('data',b=>stderr+=b);c.on('error',reject);
  c.once('exit',code=>{clearTimeout(timer);try{assert.equal(code,0,stdout+stderr);const entries=stdout.trim().split('\n').map(line=>JSON.parse(line));resolve({...entries.at(-1),cycles:entries.length,heap:stderr.trim()});}catch(e){reject(e);}});
 });results.push({mode,scenario:opts.scenario||mode,...report});return report;
}
const realExitArtifacts=[];
for(const httpVersion of ['1.1',null]) {
const firstResult=results.length;
const peer=await startRealExit({type:'tls',tlsRaw:false,tlsLogJa3:true,tlsHttpVers:httpVersion,cert:pki.certificate,key:pki.privateKey,sharedHmacKey:secret,onPacket(p,c){c.send({inject:p.toString('base64')});}});
try {
 for(let i=0;i<10;i++) { const r=await client(peer.port);assert.equal(r.alpn,httpVersion==='1.1'?'http/1.1':'h2');assert.equal(r.ja3,'ed63604b6e93c62437468be3f6b387c3');assert.equal(r.ja4,'t13d1517h2_8daaf6152771_cb7bf5808d99'); }
 assert.equal(peer.packets.length,640);
 const repeated=await client(peer.port,'repeat');assert.equal(repeated.cycles,20);assert.equal(peer.packets.length,1920);
 if(httpVersion===null){await client(peer.port,'bulk');assert.equal(peer.packets.length,2944);}
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
 const hellos=results.slice(firstResult).reduce((n,r)=>n+r.hellos*r.cycles,0);
 assert.equal(ja3.length,hellos);assert.equal(ja4.length,hellos);
 for(const value of ja3)assert.equal(value,'ed63604b6e93c62437468be3f6b387c3');
 for(const value of ja4)assert.equal(value,'t13d1517h2_8daaf6152771_cb7bf5808d99');
 realExitArtifacts.push(peer.dir);
}finally{await peer.close();}
}
// Real TLS peers exercise protocol rejection and cancellation without a VPS.
for(const mode of ['no-alpn','cover','duplicate','chunked','truncated','oversize','disconnect','invalid','backpressure','slow','cancel_auth','expired','future','folded']) {
 const sockets=new Set();
 const server=tls.createServer({cert:fs.readFileSync(['expired','future'].includes(mode)?path.join(dir,'pki',mode+'.pem'):pki.certificate),key:fs.readFileSync(pki.privateKey),minVersion:'TLSv1.3',ALPNProtocols:mode==='no-alpn'?[]:['http/1.1']},s=>{
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
 try {const r=await client(server.address().port,['disconnect','invalid','backpressure','cancel_auth'].includes(mode)?mode:'reject');if(mode==='no-alpn')assert.equal(r.phase,'unsupported_alpn');if(mode==='invalid')assert.equal(r.phase,'invalid_frame');if(mode==='backpressure')assert.equal(r.phase,'tx_timeout');}
 finally {for(const s of sockets)s.destroy();await new Promise(r=>server.close(r));}
}

// Real HTTP/2 peers: HPACK, DATA flow control and close/error semantics.
for(const mode of ['small-window','delayed-ack','cover','denied','missing-type','content-length',
                  'headers-limit','end','reset','goaway','reset-after','goaway-after',
                  'zero-window','cancel-auth','cancel-ready','ping']) {
 const sessions=new Set();let premature=false,pingAck=false,ackSent=false;
 const server=http2.createSecureServer({cert:fs.readFileSync(pki.certificate),key:fs.readFileSync(pki.privateKey),
   minVersion:'TLSv1.3',settings:{initialWindowSize:mode==='zero-window'?0:1024}});
 server.on('session',session=>{sessions.add(session);session.on('error',()=>{});session.on('close',()=>sessions.delete(session));});
 server.on('stream',(stream,headers)=>{
  stream.on('error',()=>{});
  assert.equal(headers[':method'],'POST');assert.equal(headers[':path'],'/clean-vpn');
  assert.match(headers.authorization,/^Bearer [0-9a-f]{32}$/);
  stream.on('data',b=>{
   if(!ackSent)premature=true;
   if(mode==='reset-after'){stream.close(http2.constants.NGHTTP2_CANCEL);return;}
   if(mode==='goaway-after'){stream.session.goaway();return;}
   if(['small-window','delayed-ack','ping'].includes(mode))stream.write(b);
  });
  if(mode==='cancel-auth')return;
  if(mode==='reset'){stream.close(http2.constants.NGHTTP2_CANCEL);return;}
  if(mode==='goaway'){stream.session.goaway();return;}
  const respond=()=>{
   if(stream.destroyed)return;
   const headers={':status':mode==='denied'?403:200};
   if(mode!=='missing-type')headers['content-type']=mode==='cover'?'text/plain':'application/octet-stream';
   if(mode==='content-length')headers['content-length']='0';
   if(mode==='headers-limit')headers['x-large']='a'.repeat(6000);
   ackSent=true;stream.respond(headers,{endStream:mode==='end'});
   if(mode==='ping')stream.session.ping(Buffer.from('12345678'),error=>{pingAck=!error;});
  };
  if(mode==='delayed-ack')setTimeout(respond,150);else respond();
 });
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try {
  const testMode=mode==='small-window'?'bulk':['delayed-ack','ping'].includes(mode)?'success':
    mode==='zero-window'?'backpressure':mode==='cancel-auth'?'cancel_auth':mode==='cancel-ready'?'cancel':
    ['reset-after','goaway-after'].includes(mode)?'disconnect':'reject';
  const r=await client(server.address().port,testMode,{scenario:'h2-'+mode});
  assert.equal(r.alpn,'h2');assert.equal(premature,false);
  if(mode==='zero-window')assert.equal(r.phase,'h2_flow_timeout');
  if(mode==='headers-limit')assert.equal(r.phase,'h2_headers_limit');
  if(mode==='ping')assert.equal(pingAck,true);
 }finally {for(const session of sessions)session.destroy();await new Promise(r=>server.close(r));}
}
// Raw TLS peers send invalid HTTP/2 frames. nghttp2 must reject before any IP
// callback, even when the invalid frame spans TLS records or has HPACK Huffman.
function frame(type,flags,stream,payload=Buffer.alloc(0)) {
 const h=Buffer.alloc(9);h.writeUIntBE(payload.length,0,3);h[3]=type;h[4]=flags;h.writeUInt32BE(stream,5);
 return Buffer.concat([h,payload]);
}
for(const mode of ['data-before-ack','bad-hpack','continuation','settings-limit','ping-flood','zero-update','push','frame-size']) {
 const sockets=new Set();
 const server=tls.createServer({cert:fs.readFileSync(pki.certificate),key:fs.readFileSync(pki.privateKey),
  minVersion:'TLSv1.3',ALPNProtocols:['h2']},socket=>{
   sockets.add(socket);socket.on('error',()=>{});socket.on('close',()=>sockets.delete(socket));
   let handled=false;
   socket.on('data',()=>{
    if(handled)return;handled=true;
    const settings=frame(4,0,0);
    let bad;
    if(mode==='data-before-ack')bad=frame(0,0,1,Buffer.from('bad'));
    if(mode==='bad-hpack')bad=frame(1,4,1,Buffer.from([0x80])); // invalid HPACK index 0
    if(mode==='continuation')bad=Buffer.concat([frame(1,0,1),...Array.from({length:10},()=>frame(9,0,1))]);
    if(mode==='settings-limit')bad=frame(4,0,0,Buffer.alloc(6*33));
    if(mode==='ping-flood')bad=Buffer.concat(Array.from({length:64},()=>frame(6,0,0,Buffer.alloc(8))));
    if(mode==='zero-update')bad=frame(8,0,0,Buffer.alloc(4));
    if(mode==='push')bad=frame(5,4,1,Buffer.from([0,0,0,2,0x88]));
    if(mode==='frame-size')bad=frame(0,0,1,Buffer.alloc(16385));
    socket.write(Buffer.concat([settings,bad]));
   });
  });server.on('tlsClientError',()=>{});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try {await client(server.address().port,'reject',{scenario:'h2-raw-'+mode});}
 finally{for(const s of sockets)s.destroy();await new Promise(r=>server.close(r));}
}
const idle=new Set();const server=net.createServer(s=>{idle.add(s);s.on('error',()=>{});s.on('close',()=>idle.delete(s));});await new Promise(r=>server.listen(0,'127.0.0.1',r));
try {const r=await client(server.address().port,'cancel_handshake');assert.equal(r.phase,'handshake_wait');}
finally{for(const s of idle)s.destroy();await new Promise(r=>server.close(r));}
fs.writeFileSync(path.join(dir,'result.json'),JSON.stringify({scope:'Production profiled session + real JS exit, in-memory TUN; no board/NAT',results,realExitArtifacts},null,2));
console.log('Profiled TLS tunnel tests passed: '+dir);
