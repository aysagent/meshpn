import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {installNative} from './lib/native-install.mjs';
test('fresh clock install relocates private inputs, keeps mutable state separate, never enables',t=>{
 const base=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'native-clock-install-')));t.after(()=>fs.rmSync(base,{recursive:true,force:true}));
 const put=(p,s,mode=0o600)=>fs.writeFileSync(p,s,{mode});
 const make=name=>{const root=base+'/'+name;fs.mkdirSync(root,{mode:0o700});fs.mkdirSync(root+'/opt');fs.mkdirSync(root+'/etc/systemd/system',{recursive:true});
  for(const n of ['net','guard'])put(root+'/etc/systemd/system/'+n+'.service','[Service]\nExecStart=/bin/true\n',0o644);
  put(root+'/engine',`#!/bin/sh\nif [ "$1" = --capabilities ]; then echo '{"engine":"clean-vpn-native-m1","packet_ipc":false,"service_mode":true,"dns_socket_mark":"0x43564e","experimental_transports":{"combo-tls":{"site_provisioning":true}}}'; fi\n`,0o755);
  put(root+'/ca','fixture');put(root+'/psk',Buffer.alloc(32,1));put(root+'/identity','private fixture');
  const pin=Buffer.concat([Buffer.from('0000000b7373682d6564323535313900000020','hex'),Buffer.alloc(32,2)]).toString('base64');
  put(root+'/pin','clean-vpn-clock ssh-ed25519 '+pin+'\n');
  put(root+'/clock.json',JSON.stringify({version:1,host:'192.0.2.1',port:22,user:'cvpn-clock',identity:root+'/identity',known_hosts:root+'/pin'}));
  put(root+'/client.json',JSON.stringify({version:1,role:'client',address:'192.0.2.1',ca:root+'/ca',secret_path:root+'/psk'}));
  return {root,name,binary:root+'/engine',config:root+'/client.json',clockProfile:root+'/clock.json',networkUnit:'net.service',guardUnit:'guard.service'};};
 const combo=make('combo'),packet={...JSON.parse(fs.readFileSync(combo.config)),port:443,tun:'tun0',dns:true};delete combo.networkUnit;delete combo.guardUnit;combo.hostProfile=combo.root+'/host.json';put(combo.root+'/relay.psk',Buffer.alloc(32,2));
 put(combo.root+'/host.json',JSON.stringify({version:1,guard_unit:'guard.service',guard_script:'/usr/local/bin/clean-vpn-killswitch.sh'}));
 put(combo.config,JSON.stringify({version:1,role:'client',transport:'combo-tls',boring:packet,transparent:{version:1,role:'client',transport:'transparent-tls',secret_path:combo.root+'/relay.psk',listen:{ipv4:'0.0.0.0',port:14443},exit:{ipv4:packet.address,port:packet.port},destination_policy:{mode:'public-https',deny_ipv4:[]}}}));
 // Host-owned combo uses the same conditional clock handoff.
 assert.equal(installNative(combo).status,'eligible');
 installNative({...combo,apply:true});assert.match(fs.readFileSync(combo.root+'/etc/systemd/system/native-combo.service','utf8'),/--clock-recovery/);
 const a=make('a');assert.equal(installNative(a).status,'eligible');assert.equal(fs.existsSync(a.root+'/opt/clean-vpn-native'),false);
 installNative({...a,apply:true});const target=a.root+'/opt/clean-vpn-native/a',config=JSON.parse(fs.readFileSync(target+'/clock.json'));
 assert.equal(config.consumer_unit,'native-a.service');assert.equal(config.identity,'/opt/clean-vpn-native/a/clock-identity');assert.equal(config.update_directory,'/opt/clean-vpn-native/a/binary-updates');
 assert.equal(fs.statSync(target+'/clock-identity').mode&0o777,0o600);assert.equal(fs.statSync(target+'/clock-state').mode&0o777,0o700);
 assert.match(fs.readFileSync(a.root+'/etc/systemd/system/native-a.service','utf8'),/--service --clock-recovery/);
 const recovery=fs.readFileSync(a.root+'/etc/systemd/system/native-a-clock.service','utf8');assert.match(recovery,/Before=native-a.service/);assert.doesNotMatch(recovery,/WantedBy=/);
 assert.equal(fs.existsSync(a.root+'/etc/systemd/system/multi-user.target.wants'),false);
 const manifest=JSON.parse(fs.readFileSync(target+'/installed.json'));assert.equal(manifest.clockUnit,'native-a-clock.service');assert.deepEqual(manifest.mutableDirectories,[{name:'clock-state',mode:448,purpose:'clock-budget-and-floor-no-reset'}]);
 for(const [name,mutate,pattern]of [
  ['host',o=>{const c=JSON.parse(fs.readFileSync(o.clockProfile));c.host='192.0.2.2';put(o.clockProfile,JSON.stringify(c));},/clock_profile_invalid/],
  ['permissions',o=>fs.chmodSync(o.root+'/identity',0o644),/unsafe_source/],
  ['pin',o=>put(o.root+'/pin','untrusted ssh-ed25519 xxx'),/clock_single_raw_ed25519_pin/],
  ['collision',o=>put(o.root+'/etc/systemd/system/native-collision-clock.service','foreign'),/instance_already_present/],
  ['exit',o=>put(o.config,JSON.stringify({role:'exit',address:'192.0.2.1'})),/clock_external_packet_client_only/]
 ]){const o=make(name);mutate(o);assert.throws(()=>installNative({...o,apply:true}),pattern);assert.equal(fs.existsSync(o.root+'/opt/clean-vpn-native'),false);}
});
