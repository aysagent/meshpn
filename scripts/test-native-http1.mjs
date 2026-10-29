// Independent Node HTTP/1.1/TLS peer; production HTTP and packet I/O are C++.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import {randomBytes,createHmac} from 'node:crypto';
import {execFileSync,spawn} from 'node:child_process';
import {once} from 'node:events';
import {setTimeout as delay} from 'node:timers/promises';
const build=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build');
function fixture(t){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-h1-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const cert=dir+'/cert',key=dir+'/key',psk=dir+'/psk',secret=randomBytes(32);execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],{stdio:'pipe'});fs.writeFileSync(psk,secret,{mode:0o600});return{dir,cert,key,secret,common:{version:1,http_version:'1.1',address:'127.0.0.1',tun:'cvtest0',secret_path:psk}};}
function bearer(secret,socket,window,unbound=false){return 'Bearer '+createHmac('sha256',secret).update(Buffer.concat([Buffer.from('clean-vpn-tls-v2:'),unbound?Buffer.alloc(32):socket.exportKeyingMaterial(32,'EXPORTER-clean-vpn-bind'),Buffer.from(':'+window)])).digest('hex').slice(0,32);}
function run(t,f,config,mode){const file=f.dir+'/config.json';fs.writeFileSync(file,JSON.stringify(config));const child=spawn(build+'/integration-test',[build+'/clean-vpn-engine-fixture',file,mode]);let output='';for(const s of[child.stdout,child.stderr])s.on('data',b=>{output+=b;if(output.length>65536)child.kill('SIGKILL');});const timer=setTimeout(()=>child.kill('SIGKILL'),12000);t.after(()=>{clearTimeout(timer);child.kill('SIGKILL');});const done=once(child,'close').then(([code])=>{clearTimeout(timer);assert.equal(code,0,output);return output;});done.catch(()=>{});return{done,async listening(){for(let n=0;n<100;n++){if(output.includes('native exit listening'))return;await delay(25);}throw Error('listener timeout: '+output);}};}
async function port(){const s=net.createServer();s.listen(0,'127.0.0.1');await once(s,'listening');const p=s.address().port;await new Promise(r=>s.close(r));return p;}
function packet(){const p=Buffer.alloc(64);for(let i=20;i<64;i++)p[i]=(i*17+7)%251;p[0]=0x45;p.writeUInt16BE(64,2);p[8]=64;p[9]=17;Buffer.from([10,99,0,2,1,1,1,1]).copy(p,12);let sum=0;for(let i=0;i<20;i+=2)sum+=p.readUInt16BE(i);while(sum>>>16)sum=(sum&65535)+(sum>>>16);p.writeUInt16BE((~sum)&65535,10);return Buffer.concat([Buffer.from([0,0,0,64]),p]);}
for(const kind of['valid','clock-skew','wrong-key','unbound','length-conflict','duplicate-auth','folded-header','no-alpn'])test(`HTTP/1.1 native exit versus independent peer: ${kind}`,{timeout:15000},async t=>{
 const f=fixture(t),p=await port(),native=run(t,f,{...f.common,role:'exit',port:p,cert:f.cert,key:f.key},kind==='valid'?'exit-confirmed':'exit-denied');await native.listening();
 const socket=tls.connect({host:'127.0.0.1',port:p,servername:'localhost',ca:fs.readFileSync(f.cert),minVersion:'TLSv1.3',...(kind==='no-alpn'?{}:{ALPNProtocols:['http/1.1']})});socket.on('error',()=>{});t.after(()=>socket.destroy());await once(socket,'secureConnect');
 const window=Math.floor(Date.now()/900000)+(kind==='clock-skew'?-52:0),auth=bearer(kind==='wrong-key'?randomBytes(32):f.secret,socket,window,kind==='unbound');
 if(kind==='valid'){
  assert.equal(socket.alpnProtocol,'http/1.1');
  const request=http.request({host:'localhost',port:p,path:'/clean-vpn',method:'POST',createConnection:()=>socket,headers:{host:'localhost','transfer-encoding':'chunked','content-type':'application/octet-stream','x-clean-vpn-protocol':'h1-v1',authorization:auth,'x-clean-vpn-window':String(window),connection:'keep-alive'}});
  request.on('error',()=>{});request.on('response',res=>{assert.equal(res.statusCode,200);assert.equal(res.headers['transfer-encoding'],'chunked');res.on('error',()=>{});request.write(packet());});request.flushHeaders();t.after(()=>request.destroy());
 }else{
  let output='';socket.on('data',b=>{output+=b;assert(output.length<16384);});
  const extra=kind==='length-conflict'?'Content-Length: 0\r\n':kind==='duplicate-auth'?`Authorization: ${auth}\r\n`:kind==='folded-header'?' folded\r\n':'';
  socket.write(`POST /clean-vpn HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nX-Clean-Vpn-Protocol: h1-v1\r\nAuthorization: ${auth}\r\nX-Clean-Vpn-Window: ${window}\r\n${extra}\r\n`);
  await native.done;
  if(kind==='clock-skew'){assert.match(output,/HTTP\/1.1 409 Conflict/);assert.match(output,/x-clean-vpn-error: clock-skew/);}else assert.doesNotMatch(output,/HTTP\/1.1 (200|409)/);
  return;
 }
 await native.done;
});

test('native HTTP/1.1 request accepted by independent Node HTTPS parser; exporter binding checked', {timeout:15000},async t=>{
 const f=fixture(t),sockets=new Set();let requests=0;
 const server=https.createServer({cert:fs.readFileSync(f.cert),key:fs.readFileSync(f.key),ALPNProtocols:['http/1.1']},(req,res)=>{
  assert.equal(req.method,'POST');assert.equal(req.url,'/clean-vpn');assert.equal(req.httpVersion,'1.1');assert.equal(req.socket.alpnProtocol,'http/1.1');assert.equal(req.headers['transfer-encoding'],'chunked');assert.equal(req.headers['x-clean-vpn-protocol'],'h1-v1');assert.equal(req.headers.authorization,bearer(f.secret,req.socket,req.headers['x-clean-vpn-window']));requests++;
  res.writeHead(200,{'content-type':'application/octet-stream','x-clean-vpn-protocol':'h1-v1'});res.flushHeaders();
 });server.on('connection',s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));});server.listen(0,'127.0.0.1');await once(server,'listening');t.after(()=>{for(const s of sockets)s.destroy();server.close();});
 await run(t,f,{...f.common,role:'client',port:server.address().port,server_name:'localhost',ca:f.cert},'client-handshake').done;assert.equal(requests,1);
});

for(const [name,headers,expected]of[
 ['clock-skew','HTTP/1.1 409 Conflict\r\nX-Clean-Vpn-Error: clock-skew\r\n','auth_clock_skew'],
 ['duplicate-length','HTTP/1.1 200 OK\r\nContent-Length: 0\r\n','h1_framing_invalid'],
 ['duplicate-header','HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n','duplicate_header'],
])test(`native HTTP/1.1 response handling: ${name}`,{timeout:15000},async t=>{
 const f=fixture(t),sockets=new Set();const server=tls.createServer({cert:fs.readFileSync(f.cert),key:fs.readFileSync(f.key),ALPNProtocols:['http/1.1']},s=>{sockets.add(s);s.on('error',()=>{});let bytes='';s.on('data',b=>{bytes+=b.toString('latin1');assert(bytes.length<=8192);if(bytes.endsWith('\r\n\r\n'))s.write(headers+'Transfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nX-Clean-Vpn-Protocol: h1-v1\r\n\r\n');});});server.listen(0,'127.0.0.1');await once(server,'listening');t.after(()=>{for(const s of sockets)s.destroy();server.close();});
 await run(t,f,{...f.common,role:'client',port:server.address().port,server_name:'localhost',ca:f.cert},'client-reject:'+expected).done;
});

for(const truncated of [false,true])test(`native HTTP/1.1 end of response: ${truncated?'truncated packet rejected':'idle and first packet wakes reconnect'}`,{timeout:15000},async t=>{
 const f=fixture(t),sockets=new Set();let requests=0;
 const server=https.createServer({cert:fs.readFileSync(f.cert),key:fs.readFileSync(f.key),ALPNProtocols:['http/1.1']},(req,res)=>{
  requests++;req.on('error',()=>{});res.on('error',()=>{});
  res.writeHead(200,{'content-type':'application/octet-stream','x-clean-vpn-protocol':'h1-v1'});res.flushHeaders();
  if(requests===1){if(truncated)res.write(Buffer.from([0,0,0]));res.end();}
  else req.pipe(res); // Fixture sends an inbound-addressed packet and checks every echoed byte.
 });server.on('connection',s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));});server.listen(0,'127.0.0.1');await once(server,'listening');t.after(()=>{for(const s of sockets)s.destroy();server.close();});
 await run(t,f,{...f.common,role:'client',port:server.address().port,server_name:'localhost',ca:f.cert},truncated?'client-event:h1_truncated_record':'client-event:h1_peer_end_stream').done;
 assert.equal(requests,2);
});
