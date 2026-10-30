import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {NativeBinaryUpdate,binaryDigest,writeDurable} from './lib/native-binary-update.mjs';
import {recoveryUnit,installFilePath,supportedUpdateManifest} from './clean-vpn-native-update.mjs';
test('nested install manifest paths stay inside the bundle',()=>{
  for(const name of ['engine','control/lib/native-host-network.mjs','units/native-host-network.service'])assert.equal(installFilePath('/opt/test',name),'/opt/test/'+name);
  for(const name of ['../engine','control/../../engine','/etc/passwd','control//a','control/./a','control/','control\\a',''])assert.throws(()=>installFilePath('/opt/test',name),/update_manifest_path/);
});
const old=Buffer.from('trusted old binary'),next=Buffer.from('trusted new binary');
function fixture(t,{running=true,fail=false}={}){
  const dir=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-binary-')));fs.chmodSync(dir,0o700);
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const bundle=dir+'/install';fs.mkdirSync(bundle,{mode:0o700});
  fs.writeFileSync(bundle+'/engine',old,{mode:0o755});fs.writeFileSync(bundle+'/config.json','private config',{mode:0o600});
  fs.writeFileSync(dir+'/candidate',next,{mode:0o700});NativeBinaryUpdate.initialize(bundle,[bundle+'/config.json']);
  const calls=[];let active=running;
  const service={validate:async()=>calls.push('validate'),running:async()=>active,
    guard:async()=>calls.push('guard'),stop:async()=>{calls.push('stop');active=false;},
    start:async()=>{calls.push('start');active=true;},ready:async()=>{calls.push('ready');if(fail&&fs.readFileSync(bundle+'/engine').equals(next))throw Error('bad_handshake');}};
  return{dir,bundle,service,calls,get active(){return active;},update:new NativeBinaryUpdate(bundle,service)};
}
test('update exact verified binary; unchanged config and protected mode',async t=>{
  const f=fixture(t);const r=await f.update.apply(f.dir+'/candidate',binaryDigest(next));
  assert.equal(r.status,'updated');assert.equal(r.restarted,true);assert.equal(f.update.pending(),null);
  assert.deepEqual(fs.readFileSync(f.bundle+'/engine'),next);assert.equal(fs.readFileSync(f.bundle+'/config.json','utf8'),'private config');
  assert.equal(fs.statSync(f.bundle+'/engine').mode&0o777,0o755);assert.equal(f.update.current(),binaryDigest(next));
});
test('stopped service stays stopped and digest mismatch never executes',async t=>{
  const f=fixture(t,{running:false});await assert.rejects(f.update.apply(f.dir+'/candidate','0'.repeat(64)),/candidate_digest/);
  assert.deepEqual(f.calls,[]);const r=await f.update.apply(f.dir+'/candidate',binaryDigest(next));
  assert.equal(r.requiresStart,true);assert.equal(f.active,false);assert.deepEqual(f.calls,['validate']);
});
test('runtime failure restores exact previous binary and service',async t=>{
  const f=fixture(t,{fail:true});await assert.rejects(f.update.apply(f.dir+'/candidate',binaryDigest(next)),/failed_rolled_back/);
  assert.deepEqual(fs.readFileSync(f.bundle+'/engine'),old);assert.equal(f.active,true);assert.equal(f.update.pending(),null);
});
test('same binary validates but does not restart',async t=>{
  const f=fixture(t);fs.writeFileSync(f.dir+'/candidate',old);assert.equal((await f.update.apply(f.dir+'/candidate',binaryDigest(old))).status,'unchanged');
  assert.deepEqual(f.calls,['validate']);
});
for(const point of ['prepared','stopped','binary-written','receipt-written','activated','committed']){
  test('process death at '+point+' and cold recovery',async t=>{
    const f=fixture(t);const module=new URL('./lib/native-binary-update.mjs',import.meta.url).href;
    const source=`import {NativeBinaryUpdate} from ${JSON.stringify(module)};
      const service={validate:async()=>{},running:async()=>true,guard:async()=>{},stop:async()=>{},start:async()=>{},ready:async()=>{}};
      const u=new NativeBinaryUpdate(process.argv[1],service,{fault:p=>{if(p===process.argv[3])process.kill(process.pid,'SIGKILL');}});
      await u.apply(process.argv[2],process.argv[4]);`;
    const child=spawnSync(process.execPath,['--input-type=module','-e',source,f.bundle,f.dir+'/candidate',point,binaryDigest(next)]);
    assert.equal(child.signal,'SIGKILL',child.stderr?.toString());
    const recovery=new NativeBinaryUpdate(f.bundle,{...f.service,running:async()=>false});
    const r=await recovery.recover({boot:true});assert.equal(r.status,point==='committed'?'committed':'rolled-back');
    assert.deepEqual(fs.readFileSync(f.bundle+'/engine'),point==='committed'?next:old);
    assert.equal(recovery.pending(),null);assert.deepEqual(f.calls,[]); // no premature boot activation
  });
}
test('foreign config edit blocks rollback, retains journal and never overwrites edit',async t=>{
  const f=fixture(t);const u=new NativeBinaryUpdate(f.bundle,f.service,{fault:p=>{if(p==='activated'){fs.writeFileSync(f.bundle+'/config.json','manual edit');throw Error('injected');}}});
  await assert.rejects(u.apply(f.dir+'/candidate',binaryDigest(next)),/config_or_unit_changed/);
  assert.ok(u.pending());assert.equal(fs.readFileSync(f.bundle+'/config.json','utf8'),'manual edit');
});
test('failed old-service restart retains rollback journal for retry',async t=>{
  const f=fixture(t);f.service.ready=async()=>{throw Error('unavailable');};
  await assert.rejects(f.update.apply(f.dir+'/candidate',binaryDigest(next)),/unavailable/);
  assert.equal(f.update.pending().phase,'rollback');assert.deepEqual(fs.readFileSync(f.bundle+'/engine'),old);
  f.service.ready=async()=>{};assert.equal((await f.update.recover()).status,'rolled-back');
});
test('symlink candidate is refused and corrupted retained artifact is refused',async t=>{
  const f=fixture(t);fs.symlinkSync(f.dir+'/candidate',f.dir+'/link');await assert.rejects(f.update.apply(f.dir+'/link',binaryDigest(next)));
  fs.chmodSync(f.update.dir+'/releases/'+binaryDigest(old),0o600);fs.writeFileSync(f.update.dir+'/releases/'+binaryDigest(old),'corrupt');
  await assert.rejects(f.update.apply(f.dir+'/candidate',binaryDigest(next)),/artifact_changed/);assert.deepEqual(f.calls,[]);
});
test('boot recovery ordered before engine and retained active through runtime update',()=>{
  const text=recoveryUnit({name:'test',bundle:'/opt/clean-vpn-native/test',node:'/usr/bin/node'});
  assert.match(text,/Before=native-test.service/);assert.match(text,/RemainAfterExit=yes/);assert.match(text,/--recover-boot test/);
});
test('short disk write removes only its partial temporary file and preserves target',t=>{
  const f=fixture(t),target=f.bundle+'/config.json',write=fs.writeFileSync;
  fs.writeFileSync=(fd,data,...rest)=>{if(typeof fd==='number'){write(fd,Buffer.from('partial'));throw Object.assign(Error('full'),{code:'ENOSPC'});}return write(fd,data,...rest);};
  try{assert.throws(()=>writeDurable(target,'new config'),{code:'ENOSPC'});}finally{fs.writeFileSync=write;}
  assert.equal(fs.readFileSync(target,'utf8'),'private config');assert.equal(fs.readdirSync(f.bundle).some(n=>n.endsWith('.new')),false);
});
test('insufficient disk refuses before service mutation or journal publication',async t=>{
  const f=fixture(t),stat=fs.statfsSync;fs.statfsSync=()=>({bavail:0,bsize:4096});
  try{await assert.rejects(f.update.apply(f.dir+'/candidate',binaryDigest(next)),/insufficient_disk/);}finally{fs.statfsSync=stat;}
  assert.deepEqual(f.calls,[]);assert.equal(f.update.pending(),null);assert.deepEqual(fs.readFileSync(f.bundle+'/engine'),old);
});

test('host combo updates preserve only declared mutable clock or replay state',()=>{
 const clock={name:'clock-state',mode:448,purpose:'clock-budget-and-floor-no-reset'},replay={name:'replay',mode:448,purpose:'durable-replay-no-automatic-reset'};
 for(const transport of ['boring-tls','combo-tls']){
  assert.ok(supportedUpdateManifest({transport,role:'client',mutableDirectories:[]}));
  assert.ok(supportedUpdateManifest({transport,role:'client',clockUnit:'clock.service',mutableDirectories:[clock]}));
  assert.equal(supportedUpdateManifest({transport,role:'exit',mutableDirectories:transport==='combo-tls'?[replay]:[]}),true);
  assert.equal(supportedUpdateManifest({transport,role:'exit',clockUnit:'clock.service',mutableDirectories:[clock]}),false);
 }
 for(const change of [{transport:'transparent-tls'},{role:'relay'},{mutableDirectories:[]},{mutableDirectories:[{...replay,mode:511}]},{mutableDirectories:[replay,clock]},{mutableDirectories:[{...replay,name:'../replay'}]}])
  assert.equal(supportedUpdateManifest({transport:'combo-tls',role:'exit',mutableDirectories:[replay],...change}),false);
});
