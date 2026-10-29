import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {setTimeout as delay} from 'node:timers/promises';
import {NativeClientManager,importClientBundle,readClientPrivate} from './lib/native-client-manager.mjs';
const put=(p,b)=>fs.writeFileSync(p,typeof b==='string'||Buffer.isBuffer(b)?b:JSON.stringify(b),{mode:0o600});
async function fixture(t,{combo=false,applyConfig}={}){
 const dir=fs.mkdtempSync(fs.realpathSync(os.tmpdir())+'/cvpn-clients-');t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 put(dir+'/existing.psk',randomBytes(32));put(dir+'/ca.pem','test CA');put(dir+'/profile.json',{kind:'profile'});
 const p={version:1,role:'exit',address:'192.0.2.1',port:443,tun:'cvexit0',cert:dir+'/cert.pem',key:dir+'/key.pem',peers:[{ipv4:'10.99.0.2',secret_path:dir+'/existing.psk'}]};
 let config=p;if(combo){put(dir+'/relay.psk',randomBytes(32));config={version:1,transport:'combo-tls',role:'exit',boring:p,transparent:{version:1,transport:'transparent-tls',role:'exit',public_name:'relay.example',peers:[{id:'initial',secret_path:dir+'/relay.psk'}],listen:{ipv4:'192.0.2.1',port:443},replay_directory:dir+'/replay',limits:{sessions:128,per_client:64},destination_policy:{mode:'public-https',deny_ipv4:[]}}};}
 put(dir+'/config.json',config);const initialized=[];
 const validateConfig=async file=>{const c=JSON.parse(readClientPrivate(file));const p=c.boring??c;for(const peer of p.peers??[])assert.equal(readClientPrivate(peer.secret_path).length,32);};
 const manager=new NativeClientManager({directory:dir+'/state',validateConfig,applyConfig,initializeRelay:async c=>initialized.push(c)});
 const init={configPath:dir+'/config.json',endpoint:'192.0.2.1',serverName:'vpn.example',caPath:dir+'/ca.pem',profilePath:dir+'/profile.json',...(combo?{relayMap:{'10.99.0.2':'initial'}}:{})};await manager.init(init);return{dir,manager,initialized,validateConfig,config};
}
test('adopts keys unchanged, allocates stable distinct IPs, exports only requested identity',async t=>{
 const f=await fixture(t),key=fs.readFileSync(f.dir+'/existing.psk');await f.manager.rename('client-2','radxa');await f.manager.add('laptop');await f.manager.add('phone');
 assert.deepEqual((await f.manager.list()).clients.map(c=>[c.name,c.ipv4]),[['radxa','10.99.0.2'],['laptop','10.99.0.3'],['phone','10.99.0.4']]);assert.deepEqual(fs.readFileSync(f.dir+'/existing.psk'),key);
 const a=await f.manager.export('laptop'),b=await f.manager.export('phone');assert.notEqual(a.files.psk,b.files.psk);assert.equal(a.config.peer_ipv4,'10.99.0.3');assert.equal(a.config.http_version,'auto');assert.ok(!JSON.stringify(await f.manager.list()).includes(a.files.psk));
 await importClientBundle(a,f.dir+'/imported',{validateConfig:async file=>{const c=JSON.parse(readClientPrivate(file));assert.equal(c.secret_path,f.dir+'/imported/psk');assert.equal(readClientPrivate(c.secret_path).length,32);}});
 assert.equal(fs.statSync(f.dir+'/imported/psk').mode&0o777,0o600);await assert.rejects(importClientBundle(a,f.dir+'/imported',{validateConfig:async()=>{}}),{code:'EEXIST'});
});
test('revocation keeps reservation, rotation changes key, rename does not rotate',async t=>{
 const f=await fixture(t);await f.manager.add('laptop');const a=await f.manager.export('laptop');await f.manager.rename('laptop','work');assert.equal((await f.manager.export('work')).files.psk,a.files.psk);await f.manager.rotate('work');assert.notEqual((await f.manager.export('work')).files.psk,a.files.psk);await f.manager.revoke('work');await assert.rejects(f.manager.export('work'),/client_not_found/);await f.manager.add('phone');assert.equal((await f.manager.export('phone')).ipv4,'10.99.0.4');
 await f.manager.revoke('client-2');await f.manager.revoke('phone');assert.deepEqual(JSON.parse(fs.readFileSync(f.dir+'/config.json')).peers,[]);
});
test('failed activation rolls back exact config and registry and acknowledges rollback',async t=>{
 const calls=[];const f=await fixture(t,{applyConfig:async x=>{calls.push(x);if(!x.rollback)throw Error('simulated_apply_error');}}),before=fs.readFileSync(f.dir+'/config.json'),registry=fs.readFileSync(f.manager.registryPath);
 await assert.rejects(f.manager.add('laptop'),/simulated_apply_error/);assert.deepEqual(fs.readFileSync(f.dir+'/config.json'),before);assert.deepEqual(fs.readFileSync(f.manager.registryPath),registry);assert.equal(calls.length,2);assert.equal(calls[1].rollback,true);assert.ok(!fs.existsSync(f.manager.journalPath));
});
test('rollback failure preserves journal; explicit recovery succeeds',async t=>{
 let broken=true;const f=await fixture(t,{applyConfig:async()=>{if(broken)throw Error('failed');}});await assert.rejects(f.manager.add('laptop'),/client_recovery_required/);assert.ok(fs.existsSync(f.manager.journalPath));await assert.rejects(f.manager.list(),/client_recovery_required/);broken=false;assert.equal((await f.manager.recover()).recovered,true);assert.equal((await f.manager.list()).clients.length,1);
});
test('foreign edits, symlinks, duplicate/invalid names fail without changing keys',async t=>{
 const f=await fixture(t);for(const n of ['a.b','../x','Laptop','a_','-bad'])await assert.rejects(f.manager.add(n),/client_name/);await assert.rejects(f.manager.add('client-2'),/client_name_exists/);
 const raw=fs.readFileSync(f.dir+'/config.json');fs.appendFileSync(f.dir+'/config.json','\n');await assert.rejects(f.manager.add('laptop'),/client_config_changed_externally/);put(f.dir+'/config.json',raw);
 fs.renameSync(f.dir+'/existing.psk',f.dir+'/original.psk');fs.symlinkSync(f.dir+'/original.psk',f.dir+'/existing.psk');await assert.rejects(f.manager.export('client-2'));
});
test('concurrent mutations reject rather than lose an allocation',async t=>{
 let release;const gate=new Promise(r=>release=r);const f=await fixture(t,{applyConfig:async()=>gate});const a=f.manager.add('first');await new Promise(r=>setTimeout(r,10));await assert.rejects(f.manager.add('second'),/client_manager_locked/);release();await a;assert.equal((await f.manager.list()).clients.length,2);
});
test('combo identity rotation uses new replay id and separate keys',async t=>{
 const f=await fixture(t,{combo:true});await f.manager.add('laptop');assert.equal(f.initialized.length,1);const a=await f.manager.export('laptop');assert.notEqual(a.files.psk,a.files['relay.psk']);assert.equal(a.config.boring.sni,'relay.example');const oldId=f.initialized[0].peers[0].id;await f.manager.rotate('laptop');assert.notEqual(f.initialized[1].peers[0].id,oldId);assert.equal(f.initialized[1].peers.length,1);assert.equal(f.initialized[1].replay_directory,f.dir+'/replay');
});
test('imports reject arbitrary host credential paths and malformed key',async t=>{
 const f=await fixture(t),b=await f.manager.export('client-2');b.config.ca='/etc/shadow';await assert.rejects(importClientBundle(b,f.dir+'/bad',{validateConfig:async()=>{}}),/client_bundle_path/);assert.ok(!fs.existsSync(f.dir+'/bad'));b.config.ca='@bundle/ca.pem';b.files.psk=Buffer.from('small').toString('base64');await assert.rejects(importClientBundle(b,f.dir+'/bad',{validateConfig:async()=>{}}),/client_key_length/);
});
test('active identity cap is independent from retained revoked reservations',async t=>{
 const f=await fixture(t);for(let i=0;i<31;i++)await f.manager.add('peer-'+i);await assert.rejects(f.manager.add('overflow'),/client_active_limit/);await f.manager.revoke('peer-0');await f.manager.add('replacement');assert.equal((await f.manager.export('replacement')).ipv4,'10.99.0.34');
});
test('SIGKILL releases lock; pending transaction can roll back after process boundary',async t=>{
 const f=await fixture(t);const script=`import {NativeClientManager} from ${JSON.stringify(new URL('./lib/native-client-manager.mjs',import.meta.url).href)};const m=new NativeClientManager({directory:process.argv[1],validateConfig:async()=>{},applyConfig:async()=>{console.log('WAITING');await new Promise(()=>{});}});setInterval(()=>{},1000);await m.add('interrupted');`;
 const child=spawn(process.execPath,['--input-type=module','-e',script,f.manager.directory],{stdio:['ignore','pipe','pipe']});let out='';child.stdout.on('data',b=>out+=b);t.after(()=>child.kill('SIGKILL'));
 for(let i=0;!out.includes('WAITING');i++){assert.ok(i<100,'child did not reach commit boundary');await delay(20);}
 const done=once(child,'close');child.kill('SIGKILL');await done;assert.ok(fs.existsSync(f.manager.journalPath));assert.equal((await f.manager.recover()).recovered,true);assert.equal((await f.manager.list()).clients.length,1);
});
test('recovery refuses unrelated edits without overwriting administrator changes',async t=>{
 const f=await fixture(t,{applyConfig:async()=>{throw Error('failure');}});await assert.rejects(f.manager.add('pending'),/client_recovery_required/);const changed=Buffer.from('{}\n');put(f.dir+'/config.json',changed);await assert.rejects(f.manager.recover(),/client_recovery_conflict/);assert.deepEqual(fs.readFileSync(f.dir+'/config.json'),changed);assert.ok(fs.existsSync(f.manager.journalPath));
});
test('external edit during candidate validation is preserved before journal commit',async t=>{
 const f=await fixture(t),changed=Buffer.from('{}\n');f.manager.validateConfig=async()=>put(f.dir+'/config.json',changed);await assert.rejects(f.manager.add('laptop'),/client_config_changed_externally/);assert.deepEqual(fs.readFileSync(f.dir+'/config.json'),changed);assert.ok(!fs.existsSync(f.manager.journalPath));assert.equal(JSON.parse(fs.readFileSync(f.manager.registryPath)).clients.length,1);
});
test('dangling recovery journal blocks listing and mutations and cannot be silently discarded',async t=>{
 const f=await fixture(t),before=fs.readFileSync(f.dir+'/config.json');fs.symlinkSync(f.dir+'/missing-journal',f.manager.journalPath);
 await assert.rejects(f.manager.list(),/client_recovery_required/);await assert.rejects(f.manager.add('laptop'),/client_recovery_required/);await assert.rejects(f.manager.recover());
 assert.ok(fs.lstatSync(f.manager.journalPath).isSymbolicLink());assert.deepEqual(fs.readFileSync(f.dir+'/config.json'),before);
 fs.unlinkSync(f.manager.journalPath);assert.equal((await f.manager.list()).clients.length,1);
});
