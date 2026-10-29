// Discovery-specific clock and independent wire observations. No system clock
// changes, production TUN, network manager or SSH bootstrap are involved.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import http2 from 'node:http2';
import {once} from 'node:events';
import {createHmac,randomBytes} from 'node:crypto';
import {execFileSync,spawn} from 'node:child_process';
import {parseFirstTlsClientHelloFromTcpBuf} from './lib/tls-clienthello-ja3.mjs';
import {observeTlsProfile} from './lib/native-tls-profile-observer.mjs';
const build=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build');
const profilePath=path.resolve('fixtures/native-tls-profiles/cold-h2.json');
function fixture(t,dates){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-discovery-boundary-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const openssl=(...args)=>execFileSync('openssl',args,{cwd:dir,stdio:'pipe',timeout:10000});
 openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','2','-subj','/CN=discovery-ca','-addext','basicConstraints=critical,CA:TRUE');
 openssl('req','-new','-newkey','rsa:2048','-nodes','-keyout','leaf.key','-out','leaf.csr','-subj','/CN=relay.example');
 fs.writeFileSync(dir+'/index','');fs.writeFileSync(dir+'/serial','01\n');
 fs.writeFileSync(dir+'/ca.cnf','[ca]\ndefault_ca=local\n[local]\ndatabase=index\nserial=serial\nnew_certs_dir=.\ncertificate=ca.pem\nprivate_key=ca.key\ndefault_md=sha256\ndefault_days=1\npolicy=policy\nx509_extensions=leaf\n[policy]\ncommonName=supplied\n[leaf]\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:relay.example\n');
 openssl('ca','-batch','-notext','-config','ca.cnf','-in','leaf.csr','-out','leaf.pem',...(dates?['-startdate',dates[0],'-enddate',dates[1]]:[]));
 const key=randomBytes(32);fs.writeFileSync(dir+'/psk',key,{mode:0o600});fs.writeFileSync(dir+'/relay.psk',randomBytes(32),{mode:0o600});
 return {dir,key,options:{cert:fs.readFileSync(dir+'/leaf.pem'),key:fs.readFileSync(dir+'/leaf.key'),minVersion:'TLSv1.3',maxVersion:'TLSv1.3'}};
}
async function freePort(){const s=net.createServer();s.listen(0,'127.0.0.1');await once(s,'listening');const p=s.address().port;await new Promise(r=>s.close(r));return p;}
async function config(f,port,httpVersion,combo){
 const boring={version:1,role:'client',address:'127.0.0.1',port,tun:'absenttun0',dns:true,ca:f.dir+'/ca.pem',server_name:'relay.example',secret_path:f.dir+'/psk',http_version:httpVersion,address_assignment:'v1',...(httpVersion==='2'?{tls_profile_path:profilePath}:{})};
 return combo?{version:1,role:'client',transport:'combo-tls',boring,transparent:{version:1,role:'client',transport:'transparent-tls',public_name:'relay.example',secret_path:f.dir+'/relay.psk',listen:{ipv4:'127.0.0.1',port:await freePort()},exit:{ipv4:'127.0.0.1',port},destinations:[{ipv4:'127.0.0.1',port:1}]}}:boring;
}
async function run(t,args){
 const child=spawn(args[0],args.slice(1));let stdout='',stderr='';child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);
 const timer=setTimeout(()=>child.kill('SIGKILL'),12000);t.after(()=>{clearTimeout(timer);child.kill('SIGKILL');});const [code]=await once(child,'close');clearTimeout(timer);
 assert.doesNotMatch(stderr,/ERROR: (?:AddressSanitizer|LeakSanitizer)|runtime error:/);return {code,stdout,stderr};
}
async function issuer(t,f,httpVersion,{clockSkew=false}={}){
 const sockets=new Set();let requests=0,connections=0;
 function fields(socket,h){
  requests++;const mode=h['x-clean-vpn-address-mode'];assert.ok(['discover-v1','session-v1'].includes(mode));
  const exp=socket.exportKeyingMaterial(32,'EXPORTER-clean-vpn-bind'),w=String(h['x-clean-vpn-window']);
  assert.ok(Math.abs(Number(w)-Math.floor(Date.now()/900000))<=1);
  assert.equal(h.authorization,'Bearer '+createHmac('sha256',f.key).update(Buffer.concat([Buffer.from('clean-vpn-tls-v2:'),exp,Buffer.from(':'+w)])).digest('hex').slice(0,32));
  const mac=createHmac('sha256',f.key).update(Buffer.concat([Buffer.from('clean-vpn-address-offer-v1\0'),Buffer.from([mode==='discover-v1'?1:2]),exp,Buffer.from([10,99,0,17])])).digest('hex');
  return {'content-type':'application/octet-stream','x-clean-vpn-address-mode':mode,'x-clean-vpn-address-offer':'v1:10.99.0.17:'+mac};
 }
 let server;
 if(httpVersion==='2'){
  server=http2.createSecureServer(f.options);server.on('session',s=>{sockets.add(s);s.on('error',()=>{});s.on('close',()=>sockets.delete(s));});
  server.on('stream',(s,h)=>{s.on('error',()=>{});const headers=fields(s.session.socket,h);s.respond(clockSkew?{':status':409,'x-clean-vpn-error':'clock-skew'}:{':status':200,...headers},{endStream:clockSkew||h['x-clean-vpn-address-mode']==='discover-v1'});});
 }else{
  server=tls.createServer({...f.options,ALPNProtocols:['http/1.1']},s=>{sockets.add(s);s.on('error',()=>{});s.on('close',()=>sockets.delete(s));let bytes='';s.on('data',b=>{bytes+=b.toString();if(!bytes.includes('\r\n\r\n'))return;s.removeAllListeners('data');const h=Object.fromEntries(bytes.split('\r\n').slice(1).filter(x=>x.includes(':')).map(x=>{const i=x.indexOf(':');return[x.slice(0,i).toLowerCase(),x.slice(i+1).trim()];}));
   const headers=fields(s,h),end=clockSkew||h['x-clean-vpn-address-mode']==='discover-v1';s.write((clockSkew?'HTTP/1.1 409 Conflict\r\nx-clean-vpn-error: clock-skew\r\ncontent-type: application/octet-stream\r\n':'HTTP/1.1 200 OK\r\n'+Object.entries(headers).map(([k,v])=>k+': '+v+'\r\n').join(''))+'Transfer-Encoding: chunked\r\nX-Clean-Vpn-Protocol: h1-v1\r\n\r\n');if(end)s.end('0\r\n\r\n');});});
 }
 server.on('connection',()=>connections++);server.on('tlsClientError',()=>{});server.listen(0,'127.0.0.1');await once(server,'listening');
 t.after(async()=>{for(const s of sockets)s.destroy();await new Promise(r=>server.close(r));});
 return {port:server.address().port,requests:()=>requests,connections:()=>connections};
}
for(const combo of [false,true])for(const httpVersion of ['2','1.1'])for(const scenario of ['expired','not-yet-valid','clock-skew'])test(`discovery clock fail-closed ${combo?'combo':'boring'} H${httpVersion} ${scenario}`,{timeout:20000},async t=>{
 const dates=scenario==='expired'?['20200101000000Z','20200102000000Z']:scenario==='not-yet-valid'?['20990101000000Z','20990102000000Z']:null;
 const f=fixture(t,dates),s=await issuer(t,f,httpVersion,{clockSkew:scenario==='clock-skew'}),c=await config(f,s.port,httpVersion,combo);
 const file=f.dir+'/client.json';fs.writeFileSync(file,JSON.stringify(c),{mode:0o600});const before=fs.readFileSync(file);
 const r=await run(t,[build+'/clean-vpn-engine','--discover-address',file]);assert.equal(r.code,1,r.stderr);assert.equal(r.stdout,'');assert.match(r.stderr,new RegExp(scenario==='expired'?'tls_verify_expired':scenario==='not-yet-valid'?'tls_verify_not_yet_valid':'auth_clock_skew'));
 assert.equal(s.connections(),1,'discovery must not retry or run clock bootstrap');assert.equal(s.requests(),scenario==='clock-skew'?1:0);assert.deepEqual(fs.readFileSync(file),before);assert.equal(fs.existsSync('/sys/class/net/absenttun0'),false);
});
for(const profileName of ['cold-h2','chromium-156-bounded-cold'])for(const combo of [false,true])test(`independent saved-profile observation: ${profileName} discovery versus full ${combo?'combo':'boring'} H2 session`,{timeout:30000},async t=>{
 const observedProfilePath=path.resolve('fixtures/native-tls-profiles/'+profileName+'.json'),observedProfile=JSON.parse(fs.readFileSync(observedProfilePath));
 const f=fixture(t),s=await issuer(t,f,'2'),captures=[],sockets=new Set();
 const proxy=net.createServer(client=>{const upstream=net.connect(s.port,'127.0.0.1');for(const socket of [client,upstream]){sockets.add(socket);socket.on('error',()=>{client.destroy();upstream.destroy();});socket.on('close',()=>sockets.delete(socket));}let bytes=Buffer.alloc(0),done=false;client.on('data',b=>{if(done)return;bytes=Buffer.concat([bytes,b]);assert.ok(bytes.length<=65536);const hello=parseFirstTlsClientHelloFromTcpBuf(bytes);if(hello.ok){captures.push(bytes.subarray(0,hello.bytesConsumed));done=true;}});client.pipe(upstream);upstream.pipe(client);});
 proxy.listen(0,'127.0.0.1');await once(proxy,'listening');t.after(async()=>{for(const socket of sockets)socket.destroy();await new Promise(r=>proxy.close(r));});
 const c=await config(f,proxy.address().port,'2',combo),file=f.dir+'/client.json';(combo?c.boring:c).tls_profile_path=observedProfilePath;fs.writeFileSync(file,JSON.stringify(c),{mode:0o600});
 const discover=await run(t,[build+'/clean-vpn-engine','--discover-address',file]);assert.equal(discover.code,0,discover.stderr);assert.equal(JSON.parse(discover.stdout).ipv4,'10.99.0.17');
 const full=combo?c.boring:c;full.peer_ipv4='10.99.0.17';full.dns=false;fs.writeFileSync(file,JSON.stringify(c),{mode:0o600});
 const session=await run(t,[build+'/integration-test',build+'/clean-vpn-engine-fixture',file,'client-handshake']);assert.equal(session.code,0,session.stdout+session.stderr);assert.equal(captures.length,2);assert.equal(s.requests(),2);
 const reports=captures.map(w=>observeTlsProfile(w,observedProfile));for(const report of reports)assert.equal(report.status,'matched',JSON.stringify(report.differences));assert.equal(reports[0][observedProfile.tls.permute_extensions?'ja3Sorted':'ja3'],reports[1][observedProfile.tls.permute_extensions?'ja3Sorted':'ja3']);assert.equal(reports[0].ja4.fingerprint,reports[1].ja4.fingerprint);
 const randoms=captures.map(w=>parseFirstTlsClientHelloFromTcpBuf(w).clientHelloBody.subarray(2,34).toString('hex'));assert.notEqual(randoms[0],randoms[1]);
 for(let i=0;i<captures.length;i++){fs.writeFileSync(f.dir+'/hello.bin',captures[i],{mode:0o600});const offline=JSON.parse(execFileSync(process.execPath,['scripts/clean-vpn-native-profile-observe.mjs',observedProfilePath,f.dir+'/hello.bin'],{encoding:'utf8'}));assert.equal(offline.status,'matched');assert.equal(offline.ja3,reports[i].ja3);}
 t.diagnostic(JSON.stringify({samples:2,ja3:reports.map(r=>r.ja3),ja3Sorted:reports[0].ja3Sorted,ja4:reports[0].ja4.fingerprint,profile:observedProfile.id,freshRandoms:true,scope:'external TCP byte proxy plus offline observer; no native self-report; saved synthetic or explicitly partial Chromium profile, not stock browser equivalence'}));
});
