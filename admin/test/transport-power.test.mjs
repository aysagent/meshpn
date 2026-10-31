import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {atomic,readJson} from '../lib/common.mjs';
import {clientTransportPlan} from '../lib/client-transport.mjs';
import {VpnSettingsTransaction} from '../lib/vpn-settings-transaction.mjs';
import {createBroker} from '../broker.mjs';
const packet={version:1,role:'client',address:'192.0.2.1',port:443,tun:'tun0',dns:true,server_name:'personal-cert.internal',sni:'relay.example',ca:'/ca',secret_path:'/packet.psk',tls_profile_path:'/profile.json'};
const redirect={interface:'usb0',subnet:'192.168.7.0/24',endpoint:packet.address,listen_port:10443,deny_ipv4:[]};
const network={version:1,exit_ip:packet.address,engine_unit:'native-test.service',network_unit:'network.service',guard_unit:'guard.service',guard_script:'/usr/local/bin/clean-vpn-killswitch.sh',combo_redirect:redirect};
const combo={version:1,transport:'combo-tls',role:'client',boring:packet,transparent:{version:1,transport:'transparent-tls',role:'client',public_name:'relay.example',secret_path:'/relay.psk',listen:{ipv4:'0.0.0.0',port:10443},exit:{ipv4:packet.address,port:443},destination_policy:{mode:'public-https',deny_ipv4:[]}}};
const temp=t=>{const d=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'mpn-mode-'));t.after(()=>fs.rmSync(d,{recursive:true,force:true}));return d;};
test('combo/boring switch selects real schemas and keeps inactive relay and current packet settings',()=>{
 const off=clientTransportPlan(combo,network,{hostname:'mpn'},'boring-tls',packet);
 assert.deepEqual(off.config,packet);assert.equal(off.network.combo_redirect,undefined);
 const updated={...packet,http_version:'1.1',tls_profile_path:'/second-profile.json'};
 const on=clientTransportPlan(off.config,off.network,off.settings,'combo-tls',updated);
 assert.deepEqual(on.config.transparent,combo.transparent);assert.deepEqual(on.config.boring,updated);assert.deepEqual(on.network.combo_redirect,redirect);
 for(const [mode,p] of [['transparent-tls',packet],['boring-tls',{...packet,address:'192.0.2.9'}],['boring-tls',{...packet,secret_path:'/other'}]])assert.throws(()=>clientTransportPlan(combo,network,{},mode,p));
 assert.throws(()=>clientTransportPlan(packet,off.network,{},'combo-tls',packet),/combo_configuration_unavailable/);
});
test('transport quiesces old owner before any file changes; failed activation restores all three files',async t=>{
 const state=temp(t),options={state,config:state+'/config',settings:state+'/settings',networkConfig:state+'/network',unit:'native-test.service',networkUnit:'network.service',managed:true};
 atomic(options.config,combo);atomic(options.settings,{hostname:'mpn'});atomic(options.networkConfig,network);
 const before=[options.config,options.settings,options.networkConfig].map(p=>fs.readFileSync(p,'utf8'));
 const off=clientTransportPlan(combo,network,{hostname:'mpn'},'boring-tls',packet);let stops=0,starts=0;
 const service={running:async()=>true,validate:async()=>{},guard:async()=>{},ready:async()=>{},stop:async()=>{if(stops++===0)assert.deepEqual([options.config,options.settings,options.networkConfig].map(p=>fs.readFileSync(p,'utf8')),before);},start:async()=>{if(++starts===1)throw Error('candidate_failed');}};
 const tx=new VpnSettingsTransaction(options,service);
 await assert.rejects(tx.apply(off.config,off.settings,off.network),/vpn_apply_failed_rolled_back/);
 assert.equal(stops,2);assert.equal(starts,2);assert.equal(tx.load(),null);
 assert.deepEqual([options.config,options.settings,options.networkConfig].map(p=>fs.readFileSync(p,'utf8')),before);
});
for(const cut of ['prepared','quiesced','written-0','written-1','written-2','activated','committed'])test(`transport process death at ${cut} restores a consistent mode`,async t=>{
 const state=temp(t),options={state,config:state+'/config',settings:state+'/settings',networkConfig:state+'/network',unit:'native-test.service',networkUnit:'network.service',managed:true};
 atomic(options.config,combo);atomic(options.settings,{hostname:'mpn'});atomic(options.networkConfig,network);
 const off=clientTransportPlan(combo,network,{hostname:'mpn'},'boring-tls',packet);
 const service={running:async()=>true,validate:async()=>{},guard:async()=>{},stop:async()=>{},start:async()=>{},ready:async()=>{}};
 const code=`import {VpnSettingsTransaction} from ${JSON.stringify(new URL('../lib/vpn-settings-transaction.mjs',import.meta.url).href)};
 const service={running:async()=>true,validate:async()=>{},guard:async()=>{},stop:async()=>{},start:async()=>{},ready:async()=>{}};
 const tx=new VpnSettingsTransaction(${JSON.stringify(options)},service,{fault:p=>{if(p===${JSON.stringify(cut)})process.exit(73)}});
 await tx.apply(${JSON.stringify(off.config)},${JSON.stringify(off.settings)},${JSON.stringify(off.network)});`;
 assert.equal(spawnSync(process.execPath,['--input-type=module','-e',code]).status,73);
 const tx=new VpnSettingsTransaction(options,service);await tx.recover();
 assert.deepEqual(readJson(options.config),cut==='committed'?off.config:combo);
 assert.deepEqual(readJson(options.networkConfig),cut==='committed'?off.network:network);assert.equal(tx.load(),null);
});
async function broker(t){
 const state=temp(t),bundle=state+'/bundle';fs.mkdirSync(bundle);fs.mkdirSync(state+'/profiles');atomic(bundle+'/installed.json',{transport:'combo-tls'});atomic(bundle+'/config.json',combo);atomic(bundle+'/network.json',network);
 let active='active',owner='active';const calls=[];
 const run=async(file,args)=>{
  calls.push([file,args]);
  if(file==='/engine'){const c=readJson(args[1]);assert(c.role==='client');return{out:'{}'};}
  if(file==='/usr/local/bin/clean-vpn-killswitch.sh')return{out:'IPv4: cvks\nIPv6: cvks'};
  if(file==='/usr/bin/systemctl'){
   if(args[0]==='show')return{out:`Type=notify\nActiveState=${args[1]==='network.service'?owner:active}\nSubState=running\nMainPID=42\nStatusText=ready\n`};
   if(args[0]==='stop'){assert.equal(readJson(bundle+'/config.json').transport==='combo-tls',!!readJson(bundle+'/network.json').combo_redirect);active=owner='inactive';}
   if(args[0]==='start'){if(args[1]==='network.service'){owner='active';setImmediate(()=>{active='active';});}else throw Error('engine_started_before_owner_prepared');}
  }
  return{out:''};
 };
 const b=await createBroker({version:1,usbAddress:'127.0.0.1',usbInterface:'lo',wifiInterface:'wlan0',state,bundle,engine:'/engine',profiles:state+'/profiles',vpnConfig:bundle+'/config.json',socket:state+'/broker.sock',vpnUnit:'native-test.service',networkUnit:'network.service',guardUnit:'guard.service',guardScript:'/usr/local/bin/clean-vpn-killswitch.sh',nativeManaged:true,publishMdns:false},{run});t.after(()=>b.close());return{b,bundle,calls};
}
test('broker switches both modes and never puts inactive credentials in public settings',async t=>{
 const {b,bundle}=await broker(t);assert.deepEqual((await b.dispatch('/status')).capabilities.transports,['boring-tls','combo-tls']);
 for(const transport of ['boring-tls','combo-tls']){
  const job=await b.dispatch('/vpn/settings',{transport,address:packet.address,port:443,serverName:packet.server_name,sni:packet.sni,profile:null});
  for(let i=0;i<300;i++){await new Promise(r=>setTimeout(r,5));if((await b.dispatch('/operations')).jobs.find(j=>j.id===job.id).status!=='running')break;}
  const state=(await b.dispatch('/operations')).jobs.find(j=>j.id===job.id);assert.equal(state.status,'passed',state.error);
  assert.equal((await b.dispatch('/settings')).vpn.transport,transport);assert.equal(!!readJson(bundle+'/network.json').combo_redirect,transport==='combo-tls');
 }
 assert.doesNotMatch(JSON.stringify(await b.dispatch('/settings')),/inactiveCombo|relay\.psk|packet\.psk/);
});
test('switching preserves an installed browser profile outside the selectable catalog',async t=>{
 const {b,bundle}=await broker(t),file=bundle+'/installed-profile.json';
 fs.writeFileSync(file,fs.readFileSync('fixtures/native-tls-profiles/cold-h2.json'));
 const raw=readJson(bundle+'/config.json');raw.boring.tls_profile_path=file;atomic(bundle+'/config.json',raw);
 const settings=await b.dispatch('/settings');assert.equal(settings.vpn.profile,'@configured');
 const job=await b.dispatch('/vpn/settings',{transport:'boring-tls',address:packet.address,port:443,serverName:packet.server_name,sni:packet.sni,profile:settings.vpn.profile});
 for(let i=0;i<300;i++){await new Promise(r=>setTimeout(r,5));if((await b.dispatch('/operations')).jobs.find(j=>j.id===job.id).status!=='running')break;}
 assert.equal((await b.dispatch('/operations')).jobs[0].status,'passed');
 assert.equal(readJson(bundle+'/config.json').tls_profile_path,file);
 assert.equal((await b.dispatch('/settings')).vpn.profile,'@configured');
});
for(const action of ['reboot','poweroff'])test(`${action} requires explicit confirmation and schedules only fixed graceful systemctl`,async t=>{
 const {b,calls}=await broker(t);
 for(const p of [{action},{action,confirm:false},{action:'shutdown -f',confirm:true},{action,confirm:true,unit:'sshd'}])await assert.rejects(b.dispatch('/device/power',p));
 assert(!calls.some(([f])=>f==='/usr/bin/systemd-run'));
 await b.dispatch('/device/power',{action,confirm:true});await new Promise(r=>setImmediate(r));
 const commands=calls.filter(([f])=>f==='/usr/bin/systemd-run');assert.equal(commands.length,1);
 assert.deepEqual(commands[0][1],['--unit=meshpn-admin-device-power','--on-active=3s','--timer-property=AccuracySec=1s','--collect','--','/usr/bin/systemctl',action]);
 await assert.rejects(b.dispatch('/device/power',{action,confirm:true}),/device_power_pending/);
});
