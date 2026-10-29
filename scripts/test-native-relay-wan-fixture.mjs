// This is a bounded Linux netns integration test, not a physical-host runner.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import {randomBytes} from 'node:crypto';
import {spawn,execFileSync} from 'node:child_process';
import {once} from 'node:events';
import {inspectPcap} from './clean-vpn-pcap-fingerprints.mjs';
const enabled=process.platform==='linux'&&process.getuid()===0&&process.env.CVPN_WAN_FIXTURE_TEST==='1';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
test('isolated WAN relay fixture preserves observed TLS fingerprints and host network',{skip:!enabled,timeout:90000},async t=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-wan-fixture-'));
 t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
 const roles=['exit','client','wrong'];for(const role of roles)fs.mkdirSync(directory+'/'+role,{mode:0o700});
 const write=(p,data)=>fs.writeFileSync(p,data,{mode:0o600});
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',directory+'/exit/key.pem','-out',directory+'/exit/cert.pem','-days','2','-subj','/CN=wan-relay.test','-addext','subjectAltName=DNS:wan-relay.test'],{stdio:'pipe'});
 fs.chmodSync(directory+'/exit/cert.pem',0o600);fs.chmodSync(directory+'/exit/key.pem',0o600);
 const psk=randomBytes(32);for(const role of roles)write(directory+'/'+role+'/psk',role==='wrong'?randomBytes(32):psk);
 for(const role of ['client','wrong'])write(directory+'/'+role+'/ca.pem',fs.readFileSync(directory+'/exit/cert.pem'));
 const snapshot=()=>['link','addr','route','rule'].map(x=>execFileSync('ip',['-j',x,'show'],{encoding:'utf8'})).concat(execFileSync('iptables-save',{encoding:'utf8'}),execFileSync('ip6tables-save',{encoding:'utf8'}));
 const before=snapshot();const reserve=net.createServer();reserve.listen(0,'127.0.0.1');await once(reserve,'listening');const port=reserve.address().port;await new Promise(r=>reserve.close(r));
 const children=[];
 const launch=(exe,args)=>{const child=spawn(exe,args);child.output='';for(const stream of [child.stdout,child.stderr])stream.on('data',b=>child.output+=b);child.done=once(child,'close');children.push(child);return child;};
 const stop=async child=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGTERM');const timer=setTimeout(()=>child.kill('SIGKILL'),5000);try{return await child.done;}finally{clearTimeout(timer);}};
 t.after(async()=>{for(const child of children.reverse())await stop(child);});
 const wait=async fn=>{for(let i=0;i<200;i++){if(fn())return;await sleep(50);}assert.fail('readiness timeout: '+children.map(c=>c.output).join('\n'));};
 const engine=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build','clean-vpn-engine');
 const args=['scripts/clean-vpn-native-relay-wan-lab.py','--engine',engine,'--exit-address','127.0.0.1','--port',String(port),'--seconds','60'];
 const exit=launch('python3',[...args,'--role','exit','--directory',directory+'/exit']);
 await wait(()=>exit.output.includes('wan-exit-ready'));
 const capture=launch('tcpdump',['-Z','root','--immediate-mode','-i','lo','-n','-p','-U','-s','65535','-c','12000','-w',directory+'/wan.pcap',`tcp port ${port}`]);
 await wait(()=>capture.output.includes('listening on'));
 const client=launch('python3',[...args,'--role','client','--directory',directory+'/client']);
 assert.equal((await client.done)[0],0,client.output);await stop(capture);
 const result=JSON.parse(client.output.trim());assert.equal(result.status,'passed');assert.equal(result.requests.length,8);
 assert.deepEqual(result.requests.map(x=>x.tls),Array.from({length:8},(_,i)=>i%2?'TLSv1.3':'TLSv1.2'));
 for(const request of result.requests){assert.equal(request.bytes,163840);assert.equal(request.sha256,'0820d92d729e3d7102ab0d71718f5bccd008b3986fcb341e9a0529de9d52ced6');}
 const original=inspectPcap(fs.readFileSync(directory+'/client/client.pcap'),{destination:'127.0.0.1',port:10443});
 const wire=inspectPcap(fs.readFileSync(directory+'/wan.pcap'),{destination:'127.0.0.1',port});
 assert.equal(original.connections.length,8);assert.equal(wire.connections.length,8);
 for(let i=0;i<8;i++){
  const a=original.connections[i],b=wire.connections[i];assert.equal(a.status,'observed');assert.equal(b.status,'observed');
  assert.equal(a.ja3,b.ja3);assert.equal(a.ja4,b.ja4);assert.deepEqual(a.alpn,b.alpn);
  assert.deepEqual(a.sni,['wan-relay.test']);assert.match(b.sni[0],/^n1\..+\.relay\.example$/);assert.equal(b.sni[0].includes('wan-relay.test'),false);
 }
 assert.match(capture.output,/0 packets dropped by kernel/);
 const wrong=launch('python3',[...args,'--role','client','--directory',directory+'/wrong']);
 assert.notEqual((await wrong.done)[0],0,wrong.output);assert.equal(wrong.output.includes('"status": "passed"'),false);
 assert.equal(exit.exitCode,null,'invalid authentication must not stop exit');
 assert.equal((await stop(exit))[0],0,exit.output);
 assert.deepEqual(snapshot(),before,'host namespace settings must remain byte-identical');
 const probe=net.createServer();probe.listen(port,'127.0.0.1');await once(probe,'listening');await new Promise(r=>probe.close(r));
 t.diagnostic(JSON.stringify({requests:8,tls12:4,tls13:4,ja3Ja4PairsMatched:8,wrongKeyRejected:true,hostNetworkUnchanged:true,portReleased:true,scope:'local-two-netns-real-native-relay-through-fixture-TCP-Unix-bridges'}));
});
