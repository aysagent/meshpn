// Production device TLS session against current native Linux engine. Mac host
// client + encrypted stdio relay into an isolated, capability-free container.
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
import {randomBytes,createHash} from 'node:crypto';
import {spawn,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createLabPKI} from '../scripts/create-vpn-lab-pki.mjs';
import {ja3FromTcpBuf} from '../../scripts/lib/tls-clienthello-ja3.mjs';
import {ja4FromTcpBuf} from '../../scripts/lib/tls-clienthello-ja4.mjs';
const [clientArg,buildArg]=process.argv.slice(2);
assert.ok(clientArg&&buildArg,'Pass compiled host client and build-native-exit-lab.sh output directory');
const client=path.resolve(clientArg),build=path.resolve(buildArg);
const device=path.resolve(new URL('../',import.meta.url).pathname),root=path.dirname(device);
const dir=fs.mkdtempSync(path.join(device,'perf-results/native-profiled-'));
const pki=await createLabPKI(path.join(dir,'pki'));
const key=randomBytes(32);fs.writeFileSync(dir+'/key',key,{mode:0o600});
fs.writeFileSync(dir+'/key.hex',key.toString('hex'),{mode:0o600});
fs.writeFileSync(dir+'/wrong.hex',randomBytes(32).toString('hex'),{mode:0o600});
const connection=process.env.MESHPN_PODMAN_CONNECTION||'meshpn-clean-vpn-lab-root';
const image=process.env.MESHPN_NATIVE_LAB_IMAGE||'localhost/meshpn-clean-vpn-lab:1f35b200e5e912e7';
const podArgs=['--connection',connection],exec=promisify(execFile);
// Optional per-container emulator when the lab VM has no binfmt registration.
// Does not change VM-wide handlers or restart other agents' containers.
const qemu=process.env.MESHPN_NATIVE_LAB_QEMU;
if(qemu)assert.ok(path.isAbsolute(qemu),'QEMU path must be absolute inside the lab VM');
const python=qemu?['/fixture-qemu','/usr/bin/python3']:['python3'];
const pod=async(...args)=>(await exec('podman',[...podArgs,...args],{timeout:30000,maxBuffer:1024*1024})).stdout.trim();
const delay=ms=>new Promise(r=>setTimeout(r,ms));
const imported=process.env.MESHPN_TEST_PROFILE?JSON.parse(fs.readFileSync(process.env.MESHPN_TEST_PROFILE)):null;
const expectedJa3=imported?.ja3||'ed63604b6e93c62437468be3f6b387c3',expectedJa4=imported?.ja4||'t13d1517h2_8daaf6152771_cb7bf5808d99';
const scenarios=[],captures=[];
for(const scenario of ['no-alps','alps','ack','stream','truncated','extra-frame','window','unknown','duplicate']) {
 const sub=path.join(dir,scenario);fs.mkdirSync(sub,{mode:0o700});
 fs.writeFileSync(sub+'/config.json',JSON.stringify({version:1,role:'exit',address:'127.0.0.1',port:8765,
  tun:'fixture0',secret_path:'/artifacts/key',peer_ipv4:'10.99.0.2',
  cert:'/artifacts/pki/valid.pem',key:'/artifacts/pki/server.key',alps:scenario!=='no-alps'}));
 let id,proxy;const relays=new Set(),sockets=new Set();const reports=[];const firstCapture=captures.length;
 try {
  const args=['run','-d','--network=none','--cap-drop=all','--platform=linux/amd64',
   '-v',`${root}:/source:ro`,'-v',`${build}:/binary:ro`,'-v',`${dir}:/artifacts`,
   '-e','CVPN_TEST_H2_OBSERVER=1'];
  if(qemu)args.push('-v',`${qemu}:/fixture-qemu:ro`,'-e','MESHPN_FIXTURE_QEMU=/fixture-qemu');
  if(!['no-alps','alps'].includes(scenario))args.push('-e',`CVPN_TEST_ALPS=${scenario}`);
  id=await pod(...args,image,...python,'/source/device/tests/helpers/native-exit-fixture.py',
   '/binary/clean-vpn-engine-fixture',`/artifacts/${scenario}`);
  let listening=false;
  for(let i=0;i<150;i++) {
   if(fs.existsSync(sub+'/engine.log')&&fs.readFileSync(sub+'/engine.log','utf8').includes('"state":"listening"')){listening=true;break;}
   await delay(100);
  }
  assert.ok(listening,'Native exit did not listen: '+(fs.existsSync(sub+'/engine.log')?fs.readFileSync(sub+'/engine.log','utf8'):await pod('logs',id)));
  proxy=net.createServer(s=>{
   sockets.add(s);let captured=false,prefix=Buffer.alloc(0);
   const relay=spawn('podman',[...podArgs,'exec','-i',id,...python,'/source/device/tests/helpers/native-exit-fixture.py','relay'],{stdio:['pipe','pipe','pipe']});
   relays.add(relay);let stderr='';relay.stderr.on('data',b=>stderr+=b);
   s.on('error',()=>{});relay.stdin.on('error',()=>{});
   s.on('data',b=>{
    if(captured)return;
    prefix=Buffer.concat([prefix,b]);assert.ok(prefix.length<=32768);
    const j3=ja3FromTcpBuf(prefix),j4=ja4FromTcpBuf(prefix);
    if(j3&&j4){captures.push({scenario,ja3:j3.ja3Digest,ja4:j4.fingerprint});captured=true;prefix=Buffer.alloc(0);}
   });
   s.pipe(relay.stdin);relay.stdout.pipe(s);
   relay.on('error',()=>s.destroy());
   relay.on('close',()=>{relays.delete(relay);s.destroy();});
   s.on('close',()=>{sockets.delete(s);relay.stdin.end();});
  });
  await new Promise(r=>proxy.listen(0,'127.0.0.1',r));
  async function run(mode,keyFile=dir+'/key.hex',name='exit.meshpn.test',ca=pki.ca) {
   const {stdout,stderr}=await exec(client,[String(proxy.address().port),ca,keyFile,name,mode],
    {env:{...process.env,MESHPN_NATIVE_EXIT:'1'},timeout:90000,maxBuffer:1024*1024});
   const entries=stdout.trim().split('\n').map(x=>JSON.parse(x));
   for(const e of entries)if(e.hellos){assert.equal(e.ja3,expectedJa3);assert.equal(e.ja4,expectedJa4);}
   reports.push({mode,entries,heap:stderr.trim()});return entries.at(-1);
  }
  if(['no-alps','alps'].includes(scenario)) {
   for(const mode of ['success','repeat','bulk','cancel','heartbeat','heartbeat-load']) {
    const r=await run(mode);assert.equal(r.alpn,'h2');assert.equal(r.alps,scenario==='alps');
    assert.equal(r.alps_bytes,scenario==='alps'?27:0);
   }
   await run('reject',dir+'/wrong.hex');
   await run('reject',dir+'/key.hex','wrong.meshpn.test');
   await run('reject',dir+'/key.hex','exit.meshpn.test',path.join(dir,'pki/other.pem'));
   await run('profile');
  } else {
   const r=await run('reject');assert.equal(r.phase,'h2_alps_invalid');assert.equal(r.sent,0);
  }
  // Independent wire capture, not merely the client's self-report.
  const hellos=reports.flatMap(r=>r.entries).reduce((n,r)=>n+r.hellos,0);
  assert.equal(captures.length-firstCapture,hellos);
 } finally {
  for(const s of sockets)s.destroy();for(const r of relays)r.kill('SIGTERM');
  if(proxy)await new Promise(r=>proxy.close(r));
  if(id){await pod('stop','--time','5',id);await pod('rm',id);}
 }
 const counts=JSON.parse(fs.readFileSync(sub+'/counts.json'));
 const valid=['no-alps','alps'].includes(scenario);
 assert.equal(counts.packets,valid?64*21+1024+64+1024:0);
 const log=fs.readFileSync(sub+'/engine.log','utf8');
 if(scenario==='alps') {
  // ALPS is acknowledged by TLS: client sends its own SETTINGS, no unsolicited ACK.
  const wire=[...log.matchAll(/fixture_h2 (\{[^\n]+\})/g)].map(m=>JSON.parse(m[1]));
  assert.ok(wire.some(x=>x.kind==='alps'&&x.receiver==='exit'&&x.hex===''));
  assert.ok(wire.some(x=>x.kind==='wire'&&x.receiver==='exit'&&x.hex.slice(6,10)==='0400'));
  assert.ok(!wire.some(x=>x.kind==='wire'&&x.receiver==='exit'&&x.hex.slice(6,10)==='0401'));
 }
 scenarios.push({scenario,counts,reports});
 fs.writeFileSync(dir+'/result.json',JSON.stringify({scope:'Device production TLS session + native engine fixture; no hardware/TUN/NAT',
  engineSha256:createHash('sha256').update(fs.readFileSync(build+'/clean-vpn-engine-fixture')).digest('hex'),scenarios,captures},null,2)+'\n');
 console.log(`Native ${scenario}: ${counts.packets} packet round-trips passed`);
}
for(const c of captures){assert.equal(c.ja3,expectedJa3);assert.equal(c.ja4,expectedJa4);}
fs.writeFileSync(dir+'/passed', 'Native interoperability and independent ClientHello checks passed\n');
console.log(`Native profiled TLS tests passed: ${dir}/result.json`);
