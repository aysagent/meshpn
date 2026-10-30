import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {atomic, readJson} from '../lib/common.mjs';
import {VpnSettingsTransaction} from '../lib/vpn-settings-transaction.mjs';
import {createBroker} from '../broker.mjs';

function fixture(t, {managed = true, running = true, fault, fail = ''} = {}) {
  const state = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'mpn-vpn-tx-'));
  t.after(() => fs.rmSync(state, {recursive: true, force: true}));
  const options = {state, config: state + '/vpn.json', settings: state + '/settings.json', unit: 'native-test.service', managed};
  const before = {role: 'client', address: '192.0.2.1', port: 443, server_name: 'old.example', sni: 'old.example'};
  const after = {...before, server_name: 'new.example', sni: 'new.example'};
  atomic(options.config, before); atomic(options.settings, {hostname: 'mpn', profile: null});
  const calls = [], service = {running: async () => running, validate: async () => {}};
  for (const op of ['guard', 'stop', 'start', 'restart', 'ready']) service[op] = async () => {
    calls.push(op); if (op === fail) throw Error('injected_failure');
  };
  const tx = new VpnSettingsTransaction(options, service, {fault});
  return {options, before, after, calls, service, tx};
}
test('running native applies after guard and readiness, removes private journal', async t => {
  const f = fixture(t); assert.deepEqual(await f.tx.apply(f.after, {hostname: 'mpn', profile: 'new.json'}), {saved: true, restarted: true});
  assert.deepEqual(f.calls, ['guard', 'guard', 'restart', 'ready']);
  assert.deepEqual(readJson(f.options.config), f.after); assert.equal(f.tx.load(), null);
  assert.equal(fs.statSync(f.options.config).mode & 0o777, 0o600);
});
for (const managed of [true, false]) test(`saving ${managed ? 'stopped native' : 'legacy candidate'} never activates service`, async t => {
  const f = fixture(t, {managed, running: false}); await f.tx.apply(f.after, {hostname: 'mpn'});
  assert.deepEqual(f.calls, []); assert.deepEqual(readJson(f.options.config), f.after);
});
test('failed restart restores exact config/settings and restarts previous config', async t => {
  const f = fixture(t, {fail: 'restart'}), original = fs.readFileSync(f.options.config, 'utf8');
  await assert.rejects(f.tx.apply(f.after, {hostname: 'changed'}), /vpn_apply_failed_rolled_back/);
  assert.equal(fs.readFileSync(f.options.config, 'utf8'), original);
  assert.deepEqual(readJson(f.options.settings), {hostname: 'mpn', profile: null});
  assert.deepEqual(f.calls, ['guard', 'guard', 'restart', 'stop', 'guard', 'start', 'ready']);
  assert.equal(f.tx.load(), null);
});
test('rollback failure retains journal and rejects subsequent apply', async t => {
  const f = fixture(t, {fail: 'ready'});
  await assert.rejects(f.tx.apply(f.after, {hostname: 'changed'}), /injected_failure/);
  assert.equal(f.tx.load().phase, 'rollback'); assert.deepEqual(readJson(f.options.config), f.before);
  await assert.rejects(f.tx.apply(f.after, {}), /vpn_transaction_recovery_required/);
  f.service.ready = async () => {};
  assert.equal((await f.tx.recover()).status, 'rolled-back');
});

// Abrupt process exit skips all finally/catch cleanup. Test every durable write
// boundary by opening the journal in a fresh transaction object afterwards.
for (const point of ['prepared', 'written-0', 'written-1', 'activated', 'committed']) {
  test(`process death at ${point} is recoverable without adopting candidate`, async t => {
    const f = fixture(t), module = new URL('../lib/vpn-settings-transaction.mjs', import.meta.url).href;
    const code = `import {VpnSettingsTransaction} from ${JSON.stringify(module)};
      const service={running:async()=>true,guard:async()=>{},restart:async()=>{},ready:async()=>{}};
      const tx=new VpnSettingsTransaction(${JSON.stringify(f.options)},service,{fault:p=>{if(p===${JSON.stringify(point)})process.exit(73);}});
      await tx.apply(${JSON.stringify(f.after)},{hostname:'changed'});`;
    assert.equal(spawnSync(process.execPath, ['--input-type=module', '-e', code]).status, 73);
    assert.equal(fs.statSync(f.tx.file).mode & 0o777, 0o600);
    const recovered = await f.tx.recover();
    assert.equal(recovered.status, point === 'committed' ? 'committed' : 'rolled-back');
    assert.deepEqual(readJson(f.options.config), point === 'committed' ? f.after : f.before);
    assert.equal((await f.tx.recover()).status, 'none');
  });
}
test('external edits block recovery before any service action or overwrite', async t => {
  const f = fixture(t);
  const before = fs.readFileSync(f.options.config, 'utf8'), settings = fs.readFileSync(f.options.settings, 'utf8');
  atomic(f.tx.file, {version: 1, phase: 'prepared', binding: f.tx.binding, running: true,
    entries: [{before, after: JSON.stringify(f.after)}, {before: settings, after: '{}'}]});
  atomic(f.options.config, {manual: true});
  await assert.rejects(f.tx.recover(), /vpn_transaction_external_change/);
  assert.deepEqual(f.calls, []); assert.deepEqual(readJson(f.options.config), {manual: true});
});
test('recovery cancels an in-progress activation instead of waiting for stable state', async t => {
  const f=fixture(t);
  const config=fs.readFileSync(f.options.config,'utf8'),settings=fs.readFileSync(f.options.settings,'utf8');
  atomic(f.tx.file,{version:1,phase:'prepared',binding:f.tx.binding,running:true,
    entries:[{before:config,after:JSON.stringify(f.after)},{before:settings,after:'{}'}]});
  f.service.running=async()=>{throw Error('activation_in_progress');};
  assert.equal((await f.tx.recover()).status,'rolled-back');
  assert.deepEqual(f.calls,['stop','guard','start','ready']);
});
test('journal cannot redirect recovery to a different config or unit', async t => {
  const f = fixture(t); atomic(f.tx.file, {version: 1, phase: 'prepared', binding: {...f.tx.binding, unit: 'sshd.service'}, running: true, entries: []});
  await assert.rejects(f.tx.recover(), /vpn_transaction_invalid/); assert.deepEqual(f.calls, []);
});
test('rollback restores absence of initial UI settings file', async t => {
  const f=fixture(t,{fail:'restart'});fs.unlinkSync(f.options.settings);
  await assert.rejects(f.tx.apply(f.after,{hostname:'mpn'}),/vpn_apply_failed_rolled_back/);
  assert.equal(fs.existsSync(f.options.settings),false);assert.deepEqual(readJson(f.options.config),f.before);
});
test('broker settings require notify and guard, and preserve stopped service', async t => {
  const f = fixture(t); fs.mkdirSync(f.options.state + '/profiles');
  let type = 'simple', active = 'active', guard = false; const calls = [];
  const b = await createBroker({version: 1, usbAddress: '192.168.7.1', usbInterface: 'usb0', wifiInterface: 'wlan0',
    vpnUnit: f.options.unit, guardUnit: 'guard.service', guardScript: '/guard', state: f.options.state,
    profiles: f.options.state + '/profiles', engine: '/engine', vpnConfig: f.options.config,
    socket: f.options.state + '/socket', nativeManaged: true, publishMdns: false}, {run: async (file, args) => {
      calls.push([file, ...args]);
      return {out: file === '/guard' ? (guard ? 'IPv4: cvks4\nIPv6: cvks4' : '') :
        file === '/usr/bin/systemctl' ? `Type=${type}\nActiveState=${active}\nSubState=running\nMainPID=123\nStatusText=ready\n` : ''};
    }});
  t.after(() => b.close());
  const payload = {address: '192.0.2.1', port: 443, serverName: 'new.example', sni: 'new.example', profile: null};
  const apply = async () => {await b.dispatch('/vpn/settings', payload); for (let i = 0; i < 100; i++) {await new Promise(r => setImmediate(r)); const s = await b.dispatch('/status'); if (s.jobs[0].status !== 'running') return s.jobs[0];} throw Error('job_timeout');};
  assert.equal((await apply()).error, 'native_notify_service_required'); type = 'notify';
  assert.equal((await apply()).error, 'enable_guard_first');
  active = 'inactive'; const result = await apply(); assert.equal(result.status, 'passed');
  assert.equal(result.result.requiresStart, true); assert.equal(result.result.applied, false);
  assert(!calls.some(c => c[0] === '/usr/bin/systemctl' && ['start','stop','restart'].includes(c[1])));
});

test('standalone admin controls network owner and keeps engine identity for readiness',async t=>{
  const f=fixture(t);fs.mkdirSync(f.options.state+'/profiles');const calls=[];
  let bindings='native-network.service guard.service',active='active';
  const broker=await createBroker({version:1,usbAddress:'192.168.7.1',usbInterface:'usb0',wifiInterface:'wlan0',
    vpnUnit:f.options.unit,networkUnit:'native-network.service',guardUnit:'guard.service',guardScript:'/guard',
    state:f.options.state,profiles:f.options.state+'/profiles',engine:'/engine',vpnConfig:f.options.config,
    socket:f.options.state+'/socket',nativeManaged:true,publishMdns:false},{run:async(file,args)=>{
      calls.push([file,...args]);if(file==='/guard')return{out:'IPv4: cvks4\nIPv6: cvks4'};
      if(file==='/usr/bin/systemctl'){
        if(args.includes('BindsTo'))return{out:bindings};
        if(['start','stop','restart'].includes(args[0])){active=args[0]==='stop'?'inactive':'active';return{out:''};}
        return{out:`Type=notify\nActiveState=${active}\nSubState=running\nMainPID=123\nStatusText=ready\n`};
      }return{out:''};
    }});
  t.after(()=>broker.close());
  const action=async a=>{await broker.dispatch('/vpn/action',{action:a});for(let i=0;i<100;i++){await new Promise(r=>setImmediate(r));const s=await broker.dispatch('/status');if(s.jobs[0].status!=='running')return s.jobs[0];}throw Error('job_timeout');};
  for(const a of ['stop','start','restart'])assert.equal((await action(a)).status,'passed');
  assert.deepEqual(calls.filter(c=>c[0]==='/usr/bin/systemctl'&&['start','stop','restart'].includes(c[1])).map(c=>c.slice(1)),[['stop','native-network.service'],['start','native-network.service'],['start','--no-block',f.options.unit],['restart','native-network.service'],['start','--no-block',f.options.unit]]);
  const status=await broker.dispatch('/status');assert.equal(status.network.ActiveState,'active');assert.equal(status.capabilities.networkOwner,true);
  bindings='guard.service';const before=calls.filter(c=>c[1]==='restart').length;
  assert.equal((await action('restart')).error,'network_owner_binding_required');assert.equal(calls.filter(c=>c[1]==='restart').length,before);
});

test('start repairs stopped engine under active owner without restarting healthy engine',async t=>{
 const f=fixture(t);fs.mkdirSync(f.options.state+'/profiles');let engineActive=false;const calls=[];
 const network='native-network.service';
 const b=await createBroker({version:1,usbAddress:'192.168.7.1',usbInterface:'usb0',wifiInterface:'wlan0',vpnUnit:f.options.unit,networkUnit:network,guardUnit:'guard.service',guardScript:'/guard',state:f.options.state,profiles:f.options.state+'/profiles',engine:'/engine',vpnConfig:f.options.config,socket:f.options.state+'/socket',nativeManaged:true,publishMdns:false},{run:async(file,args)=>{
  calls.push([file,...args]);if(file==='/guard')return{out:'IPv4: cvks4\nIPv6: cvks4'};
  if(file==='/usr/bin/systemctl'){
   if(args.includes('BindsTo'))return{out:network+' guard.service'};
   if(args[0]==='start'){if(args.at(-1)===f.options.unit)engineActive=true;return{out:''};}
   const active=args[1]===network||engineActive;
   return{out:`Type=notify\nActiveState=${active?'active':'inactive'}\nSubState=${active?'running':'dead'}\nMainPID=${active?123:0}\nStatusText=${active?'ready':''}\n`};
  }return{out:''};
 }});t.after(()=>b.close());
 for(let n=0;n<2;n++){
  await b.dispatch('/vpn/action',{action:'start'});await new Promise(r=>setImmediate(r));
  const job=(await b.dispatch('/status')).jobs[0];assert.equal(job.status,'passed',job.error);assert.equal(engineActive,true);
 }
 assert(!calls.some(c=>c.includes('restart')));
 assert.equal(calls.filter(c=>c[1]==='start'&&c.at(-1)===f.options.unit).length,2);
});

test('blocked recovery keeps diagnostics and emergency stop available without clearing journal',async t=>{
 const f=fixture(t);fs.mkdirSync(f.options.state+'/profiles');
 const config=fs.readFileSync(f.options.config,'utf8'),settings=fs.readFileSync(f.options.settings,'utf8');
 atomic(f.tx.file,{version:1,phase:'rollback',binding:f.tx.binding,running:false,entries:[{before:config,after:JSON.stringify(f.after)},{before:settings,after:'{}'}]});
 let fail=true;const calls=[];
 const b=await createBroker({version:1,usbAddress:'192.168.7.1',usbInterface:'usb0',wifiInterface:'wlan0',vpnUnit:f.options.unit,guardUnit:'guard.service',guardScript:'/guard',state:f.options.state,profiles:f.options.state+'/profiles',engine:'/engine',vpnConfig:f.options.config,socket:f.options.state+'/socket',nativeManaged:true,publishMdns:false},{run:async(file,args)=>{
  calls.push([file,...args]);if(args[0]==='stop'&&fail)throw Error('command_failed');
  return{out:file==='/guard'?'IPv4: cvks4\nIPv6: cvks4':'Type=notify\nActiveState=inactive\nSubState=dead\nMainPID=0\n'};
 }});t.after(()=>b.close());
 const s=await b.dispatch('/status');assert.deepEqual(s.vpnSettingsRecovery,{status:'blocked',error:'command_failed',pending:true});
 assert.equal((await b.dispatch('/settings')).vpn.transport,'boring-tls');
 await assert.rejects(b.dispatch('/vpn/action',{action:'start'}),/vpn_transaction_recovery_required/);
 fail=false;await b.dispatch('/vpn/action',{action:'stop'});await new Promise(r=>setImmediate(r));assert.equal((await b.dispatch('/status')).jobs[0].status,'passed');
 assert.equal(f.tx.load().phase,'rollback');assert(!calls.some(c=>['start','restart'].includes(c[1])));
});

test('combo profile edits preserve relay credentials and policy; endpoint/name migration refused',async t=>{
 const f=fixture(t);fs.mkdirSync(f.options.state+'/profiles');
 const relay={role:'client',transport:'transparent-tls',public_name:'relay.example',secret_path:'/relay.psk',exit:{ipv4:'192.0.2.1',port:443},destination_policy:{mode:'public-https'}};
 const original={version:1,transport:'combo-tls',role:'client',boring:{...f.before,sni:'relay.example'},transparent:relay};atomic(f.options.config,original);
 const calls=[];const b=await createBroker({version:1,usbAddress:'192.168.7.1',usbInterface:'usb0',wifiInterface:'wlan0',
 vpnUnit:f.options.unit,guardUnit:'guard.service',guardScript:'/guard',state:f.options.state,profiles:f.options.state+'/profiles',
 engine:'/engine',vpnConfig:f.options.config,socket:f.options.state+'/socket',nativeManaged:true,publishMdns:false},
 {run:async(file,args)=>{calls.push([file,...args]);return{out:'Type=notify\nActiveState=inactive\nSubState=dead\nMainPID=0\n'};}});t.after(()=>b.close());
 const payload={address:'192.0.2.1',port:443,serverName:'new.example',sni:'relay.example',profile:null};
 const apply=async p=>{await b.dispatch('/vpn/settings',p);for(let i=0;i<100;i++){await new Promise(r=>setImmediate(r));const job=(await b.dispatch('/status')).jobs[0];if(job.status!=='running')return job;}throw Error('job_timeout');};
 assert.equal((await apply(payload)).status,'passed');const saved=readJson(f.options.config);
 assert.deepEqual(saved.transparent,relay);assert.equal(saved.boring.server_name,'new.example');assert.equal(saved.transport,'combo-tls');assert.equal(saved.tls_profile_path,undefined);
 assert.equal((await apply({...payload,sni:'another.example'})).error,'combo_name_requires_exit_migration');
 assert.equal((await apply({...payload,address:'192.0.2.2'})).error,'endpoint_change_requires_owner_migration');
 assert.deepEqual(readJson(f.options.config),saved);
 atomic(f.options.state+'/profiles/new.json',{kind:'clean-vpn-native-tls-profile',id:'new',scenario:'fixture'});
 assert.equal((await apply({...payload,profile:'new.json'})).status,'passed');
 assert.equal(readJson(f.options.config).boring.tls_profile_path,f.options.state+'/profiles/new.json');
 assert.deepEqual(readJson(f.options.config).transparent,relay);
 await b.dispatch('/profile/import',{profile:{kind:'clean-vpn-native-tls-profile',id:'imported'}});
 for(let i=0;i<100;i++){await new Promise(r=>setImmediate(r));if((await b.dispatch('/status')).jobs[0].status!=='running')break;}
 const candidate=readJson(f.options.state+'/profile-check.json');assert.deepEqual(candidate.transparent,relay);assert.equal(candidate.boring.tls_profile_path,f.options.state+'/profile-candidate.json');
 calls.length=0;await b.dispatch('/probe',{kind:'exit'});await new Promise(r=>setImmediate(r));assert.ok(calls.some(c=>c[0]==='/bin/ping'&&c.at(-1)==='192.0.2.1'));
});
