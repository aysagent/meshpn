// Control-plane files/signals only; C++ generates and checks all tunnel packets.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import {once} from 'node:events';
import {randomBytes,createHash} from 'node:crypto';
import {spawn,execFileSync} from 'node:child_process';
const build=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build');
for(const combo of [false,true])for(const http_version of ['2','1.1'])test(`live exit peers: ${combo?'combo':'boring'} HTTP ${http_version}`,{timeout:30000},async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-reload-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const write=(name,content)=>{const filename=path.join(dir,name);fs.writeFileSync(filename,typeof content==='string'||Buffer.isBuffer(content)?content:JSON.stringify(content),{mode:0o600});return filename;};
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',dir+'/key','-out',dir+'/cert','-days','2','-subj','/CN=relay.example','-addext','subjectAltName=DNS:relay.example'],{stdio:'pipe'});
 const listener=net.createServer();listener.listen(0,'127.0.0.1');await once(listener,'listening');const port=listener.address().port;await new Promise(r=>listener.close(r));
 const peers=[2,3,3].map((last,i)=>({ipv4:`10.99.0.${last}`,secret_path:write(`psk-${i}`,randomBytes(32))}));
 const common={version:1,address:'127.0.0.1',port,tun:'cvtest0',http_version};
 const base={...common,role:'exit',cert:dir+'/cert',key:dir+'/key',peers:[peers[0]]};
 const relayPeers=[0,1,2].map(i=>({id:'r'+i,secret_path:write('relay-'+i,randomBytes(32))}));
 const relay={version:1,transport:'transparent-tls',role:'exit',listen:{ipv4:'127.0.0.1',port},public_name:'relay.example',destinations:[{ipv4:'127.0.0.1',port:1}],replay_directory:dir+'/replay',peers:[relayPeers[0]]};
 if(combo)fs.mkdirSync(dir+'/replay',{mode:0o700});
 const wrap=(packet,keys)=>combo?{version:1,transport:'combo-tls',role:'exit',boring:packet,transparent:{...relay,peers:keys}}:packet;
 // Initialize only new replay identities. Existing state is never reset.
 if(combo)for(const peer of relayPeers){const conf=write('init.json',{...relay,peers:[peer]});execFileSync(build+'/clean-vpn-engine',['--init-transparent-replay',conf],{stdio:'pipe'});}
 write('exit.json',wrap(base,[relayPeers[0]]));
 const stages={add:wrap({...base,peers:peers.slice(0,2)},relayPeers.slice(0,2)),
 invalid:wrap({...base,peers:[peers[0],peers[0]]},relayPeers.slice(0,2)),
 immutable:wrap({...base,port:port===65535?65534:port+1,peers:peers.slice(0,2)},relayPeers.slice(0,2)),
 'missing-key':wrap({...base,peers:[peers[0],{...peers[1],secret_path:dir+'/absent'}]},relayPeers.slice(0,2)),
 ...(combo?{'invalid-relay':wrap({...base,peers:[peers[0],peers[2]]},[{...relayPeers[2],id:'not-initialized'}])}:{}),
 rotate:wrap({...base,peers:[peers[0],peers[2]]},[relayPeers[0],relayPeers[2]]),
 revoke:wrap(base,[relayPeers[0]]),deny:wrap({...base,peers:[]},[])};
 for(const[name,config]of Object.entries(stages))write(name+'.json',config);
 for(const[name,i]of [['a',0],['b',1],['rotated',2]])write(name+'.json',{...common,role:'client',peer_ipv4:peers[i].ipv4,secret_path:peers[i].secret_path,ca:dir+'/cert',server_name:'relay.example',connection_mode:'persistent'});
 const cap=JSON.parse(execFileSync(build+'/clean-vpn-engine',['--capabilities'],{encoding:'utf8'}));assert.equal(cap.peer_reload.signal,'SIGHUP');assert.equal(cap.peer_reload.empty_peers,true);
 const child=spawn(build+'/integration-test',[build+'/clean-vpn-engine-fixture',dir,dir+'/exit.json','peer-reload']);let output='';for(const stream of [child.stdout,child.stderr])stream.on('data',b=>output+=b);const timer=setTimeout(()=>child.kill('SIGKILL'),25000);t.after(()=>{clearTimeout(timer);child.kill('SIGKILL');});const [code]=await once(child,'close');clearTimeout(timer);assert.equal(code,0,output);assert.match(output,/PEER_RELOAD_PASS/);
 const acks=output.split('\n').filter(l=>l.startsWith('RELOAD_ACK ')).map(l=>JSON.parse(l.slice(11)));assert.equal(acks.length,Object.keys(stages).length);
 let revision=0,active=createHash('sha256').update(JSON.stringify(wrap(base,[relayPeers[0]]))).digest('hex');
 for(const[[name,config],ack]of Object.entries(stages).map((entry,i)=>[entry,acks[i]])){
  const digest=createHash('sha256').update(JSON.stringify(config)).digest('hex');assert.equal(ack.config_sha256,digest);
  if(['invalid','immutable','missing-key','invalid-relay'].includes(name)){assert.equal(ack.status,'rejected');}else{revision++;active=digest;assert.equal(ack.status,'applied');}
  assert.equal(ack.revision,revision);assert.equal(ack.active_config_sha256,active);
 }
});

test('standalone transparent SIGHUP keeps PID and denies all with empty peers',{timeout:15000},async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-relay-reload-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));fs.mkdirSync(dir+'/replay',{mode:0o700});fs.writeFileSync(dir+'/psk',randomBytes(32),{mode:0o600});
 const listener=net.createServer();listener.listen(0,'127.0.0.1');await once(listener,'listening');const port=listener.address().port;await new Promise(r=>listener.close(r));
 const config={version:1,transport:'transparent-tls',role:'exit',listen:{ipv4:'127.0.0.1',port},public_name:'relay.example',destinations:[{ipv4:'127.0.0.1',port:1}],replay_directory:dir+'/replay',peers:[{id:'a',secret_path:dir+'/psk'}]};
 const filename=dir+'/exit.json';fs.writeFileSync(filename,JSON.stringify(config),{mode:0o600});execFileSync(build+'/clean-vpn-engine',['--init-transparent-replay',filename],{stdio:'pipe'});
 const child=spawn(build+'/clean-vpn-engine',['--config',filename,'--service']);const done=once(child,'close');let pending='',stderr='';const records=[];child.stdout.on('data',b=>{pending+=b;let i;while((i=pending.indexOf('\n'))>=0){records.push(JSON.parse(pending.slice(0,i)));pending=pending.slice(i+1);}});child.stderr.on('data',b=>stderr+=b);t.after(()=>child.kill('SIGKILL'));
 const wait=async predicate=>{for(let n=0;n<300;n++){const found=records.findIndex(predicate);if(found>=0)return records.splice(found,1)[0];assert.equal(child.exitCode,null,stderr);await new Promise(r=>setTimeout(r,10));}assert.fail('relay event deadline: '+JSON.stringify(records));};
 const startup=await wait(x=>x.event==='peer_reload_ready');assert.equal(startup.version,1);assert.equal(startup.config_sha256,createHash('sha256').update(JSON.stringify(config)).digest('hex'));
 await wait(x=>x.state==='listening');const pid=child.pid;
 for(const[next,revision,status]of [[{...config,peers:[]},1,'applied'],[{...config,public_name:'changed.example'},1,'rejected'],[config,2,'applied']]){
  fs.writeFileSync(filename+'.next',JSON.stringify(next),{mode:0o600});fs.renameSync(filename+'.next',filename);child.kill('SIGHUP');const ack=await wait(x=>x.event==='peer_reload');assert.equal(ack.status,status);assert.equal(ack.revision,revision);assert.equal(ack.config_sha256,createHash('sha256').update(JSON.stringify(next)).digest('hex'));assert.equal(child.pid,pid);
 }
 child.kill('SIGTERM');const[code]=await done;assert.equal(code,0,stderr);
});
