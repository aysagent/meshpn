// Reproducible local experiment; no board, TUN, routes or global trust changes.
import fs from 'node:fs';
import path from 'node:path';
import tls from 'node:tls';
import net from 'node:net';
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {createLabPKI} from '../../scripts/create-vpn-lab-pki.mjs';
import {checkProfile} from '../../scripts/vpn-profile-check.mjs';
import {tlsClientHandshakeProfileWithJa4FromTcpBuf} from '../../../scripts/lib/tls-clienthello-ja4.mjs';
import {parseFirstTlsClientHelloFromTcpBuf} from '../../../scripts/lib/tls-clienthello-ja3.mjs';
import {profileFileToHelperClientHelloBlock} from '../../../scripts/lib/boring-tls-clienthello-profile.mjs';
const here=path.dirname(fileURLToPath(import.meta.url));
const [outArg,mbedBin,bsslBin,helper]=process.argv.slice(2);
if(!outArg||!mbedBin||!bsslBin)throw Error('Usage: run-host.mjs NEW_OUT MBED_PROBE BSSL_PROBE [BORING_HELPER]');
const out=path.resolve(outArg);fs.mkdirSync(out,{mode:0o700});
const reference=JSON.parse(fs.readFileSync(path.join(here,'../../tests/fixtures/browser-fingerprint-reference.json')));
const pki=await createLabPKI(path.join(out,'pki'));
const reports=[];
function record(name,hello){
 const wire=tlsClientHandshakeProfileWithJa4FromTcpBuf(hello);assert(wire.ok);
 const actual=wire.ja3.components;
 const result=checkProfile(reference.profile,hello);
 if(name.startsWith('bssl-prefs-')||name.startsWith('bssl-handshake-'))assert(result.match,`Profile mismatch: ${name}`);
 const fieldDiff={};
 for(const [expected,got] of [['cipher_suites',actual.cipher_suites_decimal_grease_filtered],['extension_types',actual.extension_types_decimal_grease_filtered],['supported_groups',actual.supported_groups_decimal_grease_filtered],['signature_algorithms',wire.tls.signature_algorithms??[]],['ec_point_formats',actual.ec_point_formats_decimal]]){
  const want=reference.profile[expected];assert(Array.isArray(got),expected);
  fieldDiff[expected]={expected:want,actual:got,missing:want.filter(v=>!got.includes(v)),extra:got.filter(v=>!want.includes(v)),order_match:JSON.stringify(want)===JSON.stringify(got)};
 }
 fs.writeFileSync(path.join(out,name+'.bin'),hello);
 fs.writeFileSync(path.join(out,name+'.json'),JSON.stringify(wire,null,2));
 reports.push({name,bytes:hello.length,...result,diff:fieldDiff});
}
for(const [backend,bin,modes] of [['mbedtls',mbedBin,['tls12','tls13','prefs']],['bssl',bsslBin,['default','prefs']]]){
 for(const mode of modes)for(let i=0;i<3;i++){
  const name=`${backend}-${mode}-${i}`,file=path.join(out,name+'.bin');
  const cp=spawnSync(bin,['capture',file,mode],{timeout:10000,encoding:'utf8'});assert.equal(cp.status,0,cp.stderr);fs.writeFileSync(path.join(out,name+'.log'),cp.stderr);record(name,fs.readFileSync(file));
 }
}
const handshakes=[],exporters=new Set();
async function connectProbe(backend,bin,ca,shouldPass,group=null,mutation=null){
 let serverExporter=null,wire=Buffer.alloc(0),sockets=new Set();
 let serverDone;
 const serverHandshake=new Promise(resolve=>{serverDone=resolve;});
 const tlsServer=tls.createServer({key:fs.readFileSync(pki.privateKey),cert:fs.readFileSync(pki.certificate),minVersion:'TLSv1.3',maxVersion:'TLSv1.3',ALPNProtocols:['h2','http/1.1'],...(group?{ecdhCurve:group}:{})},s=>{
  serverExporter=s.exportKeyingMaterial(32,'EXPORTER-clean-vpn-bind').toString('hex');s.on('error',()=>{});serverDone(true);
 });
 tlsServer.on('tlsClientError',()=>serverDone(false));
 await new Promise(r=>tlsServer.listen(0,'127.0.0.1',r));
 // Loopback TCP relay records bytes without changing TLS records or transcripts.
 const srv=net.createServer(s=>{
  const upstream=net.connect(tlsServer.address().port,'127.0.0.1');
  for(const socket of [s,upstream]){sockets.add(socket);socket.on('close',()=>sockets.delete(socket));socket.on('error',()=>{s.destroy();upstream.destroy();});}
  s.on('data',b=>{if(!parseFirstTlsClientHelloFromTcpBuf(wire).ok){wire=Buffer.concat([wire,b]);if(wire.length>65536)s.destroy();}});
  s.pipe(upstream);upstream.pipe(s);
 });
 await new Promise(r=>srv.listen(0,'127.0.0.1',r));
 let stdout='',stderr='',code;
 try{
  code=await new Promise((resolve,reject)=>{const c=spawn(bin,['connect',String(srv.address().port),ca],{stdio:['ignore','pipe','pipe'],env:{...process.env,...(mutation?{MESHPN_PROFILE_MUTATE:mutation}:{})}});const timer=setTimeout(()=>c.kill('SIGKILL'),15000);c.stdout.on('data',b=>stdout+=b);c.stderr.on('data',b=>stderr+=b);c.once('error',reject);c.once('close',v=>{clearTimeout(timer);resolve(v);});});
  if(shouldPass){
   let timer;
   try{assert.equal(await Promise.race([serverHandshake,new Promise(resolve=>{timer=setTimeout(()=>resolve('timeout'),3000);})]),true,'server must complete the handshake too');}
   finally{clearTimeout(timer);}
  }
  if(shouldPass){assert.equal(code,0,stderr);const match=stdout.trim().match(/^TLSv1\.3 ([a-f0-9]{64})$/);assert(match,stdout);assert.equal(match[1],serverExporter);assert(!exporters.has(serverExporter),"Exporter reused on a fresh connection");exporters.add(serverExporter);record(`${backend}-handshake-${handshakes.length}`,wire);}
  else {
   assert.equal(code,backend==='bssl'?6:1,'negative case must fail in TLS, not by timeout/signal/setup');
   if(!mutation)assert.match(stderr,backend==='bssl'?/CERTIFICATE_VERIFY_FAILED/:/handshake error -\d+/);
   else {
    assert.match(stderr,/PROFILE_GATE hellos=\d+ match=0 sent=0 /,'mismatch must send zero TLS bytes');
    const gate=stderr.match(/PROFILE_GATE[^\n]*ja3=(\S*) ja4=(\S*)/);assert(gate);
    if(mutation==='order'){assert.notEqual(gate[1],reference.profile.ja3_md5);assert.equal(gate[2],reference.profile.ja4.fingerprint);}
    if(mutation==='signature_order'){assert.equal(gate[1],reference.profile.ja3_md5);assert.notEqual(gate[2],reference.profile.ja4.fingerprint);}
   }
   assert.equal(serverExporter,null,'negative handshake reached server secure connection');
  }
  if(backend==='bssl'){const h=stderr.match(/BSSL_HEAP calls=(\d+) peak=(\d+)/);assert(h&&Number(h[1])>0&&Number(h[2])>0,"BoringSSL allocator hooks inactive");}
  fs.writeFileSync(path.join(out,`${backend}-connection-${handshakes.length}.log`),stderr);
  handshakes.push({backend,heap:stderr.match(/BSSL_HEAP.*$/m)?.[0]??null,trusted_ca:ca===pki.ca,constrained_group:group,mutation,expected_accept:shouldPass,accepted:code===0,exporter_equal:shouldPass?true:null,exit_code:code});
 }finally{for(const s of sockets)s.destroy();await new Promise(r=>srv.close(r));await new Promise(r=>tlsServer.close(r));}
}
for(const [backend,bin] of [['mbedtls',mbedBin],['bssl',bsslBin]]){
 for(let i=0;i<3;i++)await connectProbe(backend,bin,pki.ca,true);
 await connectProbe(backend,bin,path.join(out,'pki/other.pem'),false);
}
for(let i=0;i<3;i++)await connectProbe('bssl',bsslBin,pki.ca,true,'X25519MLKEM768');
await connectProbe('mbedtls',mbedBin,pki.ca,false,'X25519MLKEM768');
for(const mutation of ['order','signature_order','alpn','no_gate'])await connectProbe('bssl',bsslBin,pki.ca,false,null,mutation);
for(let i=0;i<3;i++)await connectProbe('bssl',bsslBin,pki.ca,true,'P-256'); // HelloRetryRequest
// Observe the project's current desktop helper as-is; do not patch it.
if(helper){for(let i=0;i<3;i++){
 let capture=Buffer.alloc(0),child;
 const srv=net.createServer(s=>{s.on('error',()=>{});s.on('data',b=>{capture=Buffer.concat([capture,b]);if(parseFirstTlsClientHelloFromTcpBuf(capture).ok)s.destroy();});});
 await new Promise(r=>srv.listen(0,'127.0.0.1',r));
 try{
  const chp=profileFileToHelperClientHelloBlock({...reference.profile,permute_extensions:false},{ja3Strict:false});
  const cfg={host:'127.0.0.1',port:srv.address().port,servername:'exit.meshpn.test',verify_host:'exit.meshpn.test',ca_pem:fs.readFileSync(pki.ca,'utf8'),alpn:['h2','http/1.1'],client_hello_profile:chp};
  let err='';const code=await new Promise((resolve,reject)=>{child=spawn(helper,[],{stdio:['pipe','pipe','pipe']});const timer=setTimeout(()=>child.kill('SIGKILL'),10000);child.stdout.resume();child.stderr.on('data',b=>err+=b);child.once('error',reject);child.once('close',c=>{clearTimeout(timer);resolve(c);});const body=Buffer.from(JSON.stringify(cfg)),head=Buffer.alloc(4);head.writeUInt32BE(body.length);child.stdin.on('error',()=>{});child.stdin.end(Buffer.concat([head,body]));});
  fs.writeFileSync(path.join(out,`helper-${i}.log`),err);
  assert(parseFirstTlsClientHelloFromTcpBuf(capture).ok,`helper failed before hello: ${code} ${err}`);record(`helper-${i}`,capture);
 }finally{child?.kill();await new Promise(r=>srv.close(r));}
}}
assert.equal(new Set(reports.map(r=>r.clienthello_sha256)).size,reports.length,"Each observation must be a fresh ClientHello");
const result={scope:'Host feasibility, not firmware runtime or profiled transport implementation',
 runtime:{node:process.version,openssl:process.versions.openssl,platform:process.platform,arch:process.arch},
 binaries_sha256:Object.fromEntries([['mbedtls',mbedBin],['bssl',bsslBin],...(helper?[['helper',helper]]:[])].map(([name,file])=>[name,createHash('sha256').update(fs.readFileSync(file)).digest('hex')])),
 reference_source:reference.source,reference_sha256:reference.source_sha256,reference_profile_sha256:createHash('sha256').update(JSON.stringify(reference.profile)).digest('hex'),reports,handshakes};
fs.writeFileSync(path.join(out,'result.json'),JSON.stringify(result,null,2));
console.log(JSON.stringify({out,captures:reports.length,matching:reports.filter(r=>r.match).length,handshakes},null,2));
