// Real TLS/H2 tests. Only fixture endpoints use Node; production auth is C++.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes, createHmac } from 'node:crypto';
import { spawn, execFileSync } from 'node:child_process';
import { once } from 'node:events';
import net from 'node:net';
import http2 from 'node:http2';
const build=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build');
function fixture(t){
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-clock-auth-'));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const cert=dir+'/cert',key=dir+'/key',psk=dir+'/psk',secret=randomBytes(32);
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],{stdio:'pipe'});
  fs.writeFileSync(psk,secret,{mode:0o600});
  return {dir,cert,key,secret,common:{version:1,address:'127.0.0.1',tun:'cvtest0',secret_path:psk}};
}
function bearer(secret,exp,window){
  return 'Bearer '+createHmac('sha256',secret).update(Buffer.concat([Buffer.from('clean-vpn-tls-v2:'),exp,Buffer.from(':'+window)])).digest('hex').slice(0,32);
}
function run(t,f,config,mode){
  const file=f.dir+'/config.json';fs.writeFileSync(file,JSON.stringify(config));
  const child=spawn(build+'/integration-test',[build+'/clean-vpn-engine-fixture',file,mode],{stdio:['ignore','pipe','pipe']});
  let output='';for(const s of [child.stdout,child.stderr])s.on('data',b=>{output+=b;if(output.length>65536)child.kill('SIGKILL');});
  const timer=setTimeout(()=>child.kill('SIGKILL'),12000);
  t.after(()=>{clearTimeout(timer);child.kill('SIGKILL');});
  const done=once(child,'close').then(([code])=>{clearTimeout(timer);assert.equal(code,0,output);return output;});
  // Attach a handler now, even if a TLS assertion fails before awaiting done.
  done.catch(()=>{});
  return {child,done,output:()=>output};
}
async function port(){const s=net.createServer();s.listen(0,'127.0.0.1');await once(s,'listening');const p=s.address().port;await new Promise(r=>s.close(r));return p;}
const cases=[
  ['13h behind',-52,true],['13h ahead',52,true],['RTC in 2017',null,true],
  ['wrong PSK',-52,false],['unbound MAC',-52,false],['missing window',-52,false],
  ['different claimed window',-52,false],['negative window',-52,false],
  ['leading zero',-52,false],['oversized window',-52,false],['nonnumeric window',-52,false],
  ['correct time',0,200],['legacy correct time',0,200],
];
for(const [name,delta,expected] of cases)test(`native clock diagnosis: ${name}`,{timeout:15000},async t=>{
  const f=fixture(t),p=await port();
  const native=run(t,f,{...f.common,role:'exit',port:p,cert:f.cert,key:f.key},expected===200?'exit-confirmed':'exit-denied');
  await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(Error('listener deadline: '+native.output())),5000);
    const check=()=>{if(native.output().includes('native exit listening')){clearTimeout(timer);native.child.stdout.off('data',check);resolve();}};
    native.child.stdout.on('data',check);check();
  });
  const s=http2.connect(`https://127.0.0.1:${p}`,{ca:fs.readFileSync(f.cert),servername:'localhost'});
  s.on('error',()=>{});t.after(()=>s.destroy());await once(s,'connect');
  const w=delta===null?Math.floor(1483228800/900):Math.floor(Date.now()/900000)+delta;
  const exp=name==='unbound MAC'?Buffer.alloc(32):s.socket.exportKeyingMaterial(32,'EXPORTER-clean-vpn-bind');
  const secret=name==='wrong PSK'?randomBytes(32):f.secret;
  let claimed=String(w);
  if(name==='different claimed window')claimed=String(w+5);
  if(name==='negative window')claimed='-'+claimed;
  if(name==='leading zero')claimed='0'+claimed;
  if(name==='oversized window')claimed='9999999999999999999999999';
  if(name==='nonnumeric window')claimed='yesterday';
  const headers={':method':'POST',':path':'/clean-vpn',authorization:bearer(secret,exp,w)};
  if(!['missing window','legacy correct time'].includes(name))headers['x-clean-vpn-window']=claimed;
  const req=s.request(headers);req.on('error',()=>{});let response;
  req.on('response',h=>{
    response=h;
    if(expected===200&&h[':status']===200){
      const packet=Buffer.alloc(64);
      for(let i=20;i<64;i++)packet[i]=(i*17+7)%251;
      packet[0]=0x45;packet.writeUInt16BE(64,2);packet[8]=64;packet[9]=17;
      Buffer.from([10,99,0,2,1,1,1,1]).copy(packet,12);
      let sum=0;for(let i=0;i<20;i+=2)sum+=packet.readUInt16BE(i);
      while(sum>>>16)sum=(sum&65535)+(sum>>>16);packet.writeUInt16BE((~sum)&65535,10);
      req.write(Buffer.concat([Buffer.from([0,0,0,64]),packet]));
    }
  });
  await native.done;
  if(expected===true){assert.equal(response?.[':status'],409);assert.equal(response?.['x-clean-vpn-error'],'clock-skew');}
  else if(expected===200)assert.equal(response?.[':status'],200);
  else assert.equal(response,undefined,'invalid proof must not advertise clock skew');
});
for(const advertised of ['clock-skew','wrong-key'])test(`native client classifies authenticated response: ${advertised}`,{timeout:15000},async t=>{
  const f=fixture(t),s=http2.createSecureServer({cert:fs.readFileSync(f.cert),key:fs.readFileSync(f.key)});
  const sessions=new Set();let requests=0;
  s.on('session',session=>{sessions.add(session);session.on('error',()=>{});session.on('close',()=>sessions.delete(session));});
  s.on('stream',(stream,h)=>{
    stream.on('error',()=>{});requests++;
    const w=h['x-clean-vpn-window'];assert.match(w,/^[0-9]{1,10}$/);
    assert.ok(Math.abs(Number(w)-Math.floor(Date.now()/900000))<=1);
    assert.equal(h.authorization,bearer(f.secret,stream.session.socket.exportKeyingMaterial(32,'EXPORTER-clean-vpn-bind'),w));
    stream.respond({':status':409,'x-clean-vpn-error':advertised});
  });
  s.listen(0,'127.0.0.1');await once(s,'listening');
  t.after(()=>{for(const x of sessions)x.destroy();s.close();});
  const reason=advertised==='clock-skew'?'auth_clock_skew':'vpn_response_rejected';
  const native=run(t,f,{...f.common,role:'client',port:s.address().port,server_name:'localhost',ca:f.cert},'client-reject:'+reason);
  assert.match(await native.done,/TLS rejected with expected diagnostic PASS/);assert.ok(requests>=1);
});
