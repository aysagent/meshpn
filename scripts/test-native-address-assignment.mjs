import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import {once} from 'node:events';
import {randomBytes} from 'node:crypto';
import {execFileSync,spawn} from 'node:child_process';
const build=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build');
for(const combo of [false,true])for(const http_version of ['2','1.1'])test(`native authenticated address discovery and session binding: ${combo?'combo':'boring'} H${http_version}`,{timeout:45000},async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-address-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const write=(name,data)=>{const f=dir+'/'+name;fs.writeFileSync(f,Buffer.isBuffer(data)?data:JSON.stringify(data),{mode:0o600});return f;};
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',dir+'/key','-out',dir+'/cert','-days','2','-subj','/CN=relay.example','-addext','subjectAltName=DNS:relay.example'],{stdio:'pipe'});
 const reserve=net.createServer();reserve.listen(0,'127.0.0.1');await once(reserve,'listening');const port=reserve.address().port;await new Promise(r=>reserve.close(r));
 const a=write('a.psk',randomBytes(32)),b=write('b.psk',randomBytes(32)),wrong=write('wrong.psk',randomBytes(32)),relay=write('relay.psk',randomBytes(32));
 const common={version:1,address:'127.0.0.1',port,tun:'absenttun0',http_version};
 const exit={...common,role:'exit',cert:dir+'/cert',key:dir+'/key',peers:[{ipv4:'10.99.0.2',secret_path:a},{ipv4:'10.99.0.3',secret_path:b}]};
 const client={...common,role:'client',ca:dir+'/cert',server_name:'relay.example',secret_path:b,address_assignment:'v1',
  ...(http_version==='2'?{tls_profile_path:path.resolve('fixtures/native-tls-profiles/cold-h2.json')}:{})};
 const transparent={version:1,transport:'transparent-tls',public_name:'relay.example',secret_path:relay,destinations:[{ipv4:'127.0.0.1',port:1}]};
 const wrap=c=>combo?{version:1,transport:'combo-tls',role:c.role,boring:c,transparent:{...transparent,role:c.role,listen:{ipv4:'127.0.0.1',port:c.role==='exit'?port:0},...(c.role==='exit'?{replay_directory:dir+'/replay'}:{exit:{ipv4:'127.0.0.1',port}})}}:c;
 // Existing combo config requires a nonzero private relay listener; fixture
 // clients use distinct free ports, while discovery must never bind its port.
 const ports=[];for(let i=0;i<7;i++){const s=net.createServer();s.listen(0,'127.0.0.1');await once(s,'listening');ports.push(s.address().port);await new Promise(r=>s.close(r));}
 const store=(name,c)=>{const value=wrap(c);if(combo&&c.role==='client')value.transparent.listen.port=ports.shift();return write(name,value);};
 store('exit.json',exit);store('a.json',{...client,secret_path:a,peer_ipv4:'10.99.0.2'});store('b.json',{...client,peer_ipv4:'10.99.0.3'});
 store('discover.json',{...client,dns:true});store('mismatch.json',{...client,peer_ipv4:'10.99.0.4'});store('wrong-key.json',{...client,secret_path:wrong});store('wrong-name.json',{...client,server_name:'wrong.example'});
 store('revoke.json',{...exit,peers:[exit.peers[0]]});
 if(combo){fs.mkdirSync(dir+'/replay',{mode:0o700});execFileSync(build+'/clean-vpn-engine',['--init-transparent-replay',dir+'/exit.json'],{stdio:'pipe'});}
 const cap=JSON.parse(execFileSync(build+'/clean-vpn-engine',['--capabilities'],{encoding:'utf8'}));assert.equal(cap.address_assignment.discovery_cli,true);assert.equal(cap.address_assignment.session_proof,true);
 const child=spawn(build+'/integration-test',[build+'/clean-vpn-engine-fixture',dir,dir+'/exit.json','address-assignment',build+'/clean-vpn-engine']);let output='';for(const stream of [child.stdout,child.stderr])stream.on('data',b=>output+=b);
 const timeout=setTimeout(()=>child.kill('SIGKILL'),40000);t.after(()=>{clearTimeout(timeout);child.kill('SIGKILL');});const [code]=await once(child,'close');clearTimeout(timeout);assert.equal(code,0,output);assert.match(output,/ADDRESS_ASSIGNMENT_PASS/);
});

// Independent TLS/HTTP issuer: never use the native offer encoder in these
// negative tests. This exercises protocol downgrade and transcript binding.
for(const httpVersion of ['2','1.1'])for(const scenario of ['valid','old-exit','missing-proof','wrong-version','wrong-key','wrong-exporter','wrong-purpose','changed-address','upper-hex','payload','incomplete','stall','cancelled'])test(`address discovery independent H${httpVersion} issuer: ${scenario}`,{timeout:15000},async t=>{
 const {createHmac}=await import('node:crypto'),tls=await import('node:tls'),http2=await import('node:http2');
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-offer-peer-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',dir+'/key','-out',dir+'/cert','-days','2','-subj','/CN=relay.example','-addext','subjectAltName=DNS:relay.example'],{stdio:'pipe'});
 const key=randomBytes(32);fs.writeFileSync(dir+'/psk',key,{mode:0o600});
 const options={key:fs.readFileSync(dir+'/key'),cert:fs.readFileSync(dir+'/cert'),minVersion:'TLSv1.3',maxVersion:'TLSv1.3',ALPNProtocols:[httpVersion==='2'?'h2':'http/1.1']};
 const sockets=new Set();let requestSeen=false;
 const offer=(socket,authorization,mode)=>{
  assert.equal(mode,'discover-v1');const binding=socket.exportKeyingMaterial(32,'EXPORTER-clean-vpn-bind');const window=Math.floor(Date.now()/900000);
  assert.equal(authorization,'Bearer '+createHmac('sha256',key).update(Buffer.concat([Buffer.from('clean-vpn-tls-v2:'),binding,Buffer.from(':'+window)])).digest('hex').slice(0,32));requestSeen=true;
  const exp=Buffer.from(binding);if(scenario==='wrong-exporter')exp[0]^=1;
  const signingKey=Buffer.from(key);if(scenario==='wrong-key')signingKey[0]^=1;
  const message=Buffer.concat([Buffer.from('clean-vpn-address-offer-v1\0'),Buffer.from([scenario==='wrong-purpose'?2:1]),exp,Buffer.from([10,99,0,3])]);
  let mac=createHmac('sha256',signingKey).update(message).digest('hex');if(scenario==='upper-hex')mac=mac.toUpperCase();
  return `v1:10.99.0.${scenario==='changed-address'?4:3}:${mac}`;
 };
 const fields=(socket,authorization,mode)=>{
  const value=offer(socket,authorization,mode);const result={'content-type':'application/octet-stream'};
  if(scenario!=='old-exit')result['x-clean-vpn-address-mode']=scenario==='wrong-version'?'discover-v2':'discover-v1';
  if(!['old-exit','missing-proof'].includes(scenario))result['x-clean-vpn-address-offer']=value;
  return result;
 };
 let server;
 if(httpVersion==='2'){
  server=http2.createSecureServer(options);server.on('session',session=>{sockets.add(session);session.on('error',()=>{});session.on('close',()=>sockets.delete(session));});
  server.on('stream',(stream,headers)=>{stream.on('error',()=>{});const response={':status':200,...fields(stream.session.socket,headers.authorization,headers['x-clean-vpn-address-mode'])};
   if(['stall','cancelled'].includes(scenario)){if(scenario==='cancelled')setTimeout(()=>child.kill('SIGTERM'),50);return;}
   if(['payload','incomplete'].includes(scenario)){stream.respond(response);if(scenario==='payload')stream.end('x');else setTimeout(()=>stream.destroy(),30);}
   else stream.respond(response,{endStream:true});
  });
 }else{
  server=tls.createServer(options,socket=>{sockets.add(socket);socket.on('error',()=>{});socket.on('close',()=>sockets.delete(socket));let buffer='';
   socket.on('data',chunk=>{buffer+=chunk.toString();if(!buffer.includes('\r\n\r\n'))return;socket.removeAllListeners('data');
    const headers=Object.fromEntries(buffer.split('\r\n').slice(1).filter(x=>x.includes(':')).map(x=>{const i=x.indexOf(':');return[x.slice(0,i).toLowerCase(),x.slice(i+1).trim()];}));
    const response=fields(socket,headers.authorization,headers['x-clean-vpn-address-mode']);
    if(['stall','cancelled'].includes(scenario)){if(scenario==='cancelled')setTimeout(()=>child.kill('SIGTERM'),50);return;}
    socket.end('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Clean-Vpn-Protocol: h1-v1\r\n'+Object.entries(response).map(([k,v])=>k+': '+v+'\r\n').join('')+'\r\n'+(scenario==='payload'?'1\r\nx\r\n0\r\n\r\n':scenario==='incomplete'?'':'0\r\n\r\n'));
   });
  });
 }
 server.on('tlsClientError',()=>{});server.listen(0,'127.0.0.1');await once(server,'listening');
 t.after(async()=>{for(const socket of sockets)socket.destroy();await new Promise(r=>server.close(r));});
 const config={version:1,role:'client',address:'127.0.0.1',port:server.address().port,tun:'absenttun0',dns:true,ca:dir+'/cert',server_name:'relay.example',secret_path:dir+'/psk',http_version:httpVersion};
 fs.writeFileSync(dir+'/client.json',JSON.stringify(config),{mode:0o600});
 const child=spawn(build+'/clean-vpn-engine',['--discover-address',dir+'/client.json']);let stdout='',stderr='';child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);const timer=setTimeout(()=>child.kill('SIGKILL'),12000);t.after(()=>{clearTimeout(timer);child.kill('SIGKILL');});
 const [code]=await once(child,'close');clearTimeout(timer);assert.equal(requestSeen,true);
 if(scenario==='valid'){assert.equal(code,0,stderr);assert.deepEqual(JSON.parse(stdout),{version:1,event:'address_discovery',status:'verified',assignment:'v1',ipv4:'10.99.0.3'});}else{assert.equal(code,1,stderr);assert.equal(stdout,'');assert.match(stderr,/address discovery refused/);}
});
