import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {installNative} from './lib/native-install.mjs';
test('host installer bundles standalone owner, publishes disabled network activation and preserves guard',t=>{
  const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'native-host-install-')));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const put=(p,b,mode=0o600)=>fs.writeFileSync(root+p,b,{mode});
  fs.mkdirSync(root+'/opt');fs.mkdirSync(root+'/etc/systemd/system',{recursive:true});
  const guard='[Service]\nType=oneshot\nExecStart=/bin/true\n';put('/etc/systemd/system/guard.service',guard,0o644);
  put('/engine',`#!/bin/sh\nif [ "$1" = --capabilities ]; then echo '{"engine":"clean-vpn-native-m1","packet_ipc":false,"service_mode":true,"dns_socket_mark":"0x43564e"}'; fi\n`,0o755);
  put('/ca','fixture');put('/psk',Buffer.alloc(32,1));
  put('/config',JSON.stringify({version:1,role:'client',address:'154.62.226.216',port:443,tun:'tun0',dns:true,ca:root+'/ca',secret_path:root+'/psk'}));
  put('/host',JSON.stringify({version:1,guard_unit:'guard.service',guard_script:'/usr/local/bin/guard.sh'}));
  const options={root,name:'daily',binary:root+'/engine',config:root+'/config',hostProfile:root+'/host'};
  assert.throws(()=>installNative({...options,networkUnit:'other.service'}),/conflicting_host_dependencies/);
  assert.equal(installNative(options).status,'eligible');assert.equal(fs.existsSync(root+'/opt/clean-vpn-native'),false);
  const result=installNative({...options,apply:true});assert.equal(result.activation,'native-daily-network.service');
  const bundle=root+'/opt/clean-vpn-native/daily',manifest=JSON.parse(fs.readFileSync(bundle+'/installed.json'));
  assert.equal(manifest.activation,result.activation);assert.equal(manifest.networkUnit,'native-daily-network.service');
  assert.deepEqual(Object.keys(manifest.dependencies),['guard.service']);
  assert.equal(fs.readFileSync(root+'/etc/systemd/system/guard.service','utf8'),guard);
  assert.equal(fs.existsSync(root+'/etc/systemd/system/multi-user.target.wants'),false);
  assert.doesNotMatch(fs.readFileSync(bundle+'/service.unit','utf8'),/WantedBy=/);
  assert.match(fs.readFileSync(root+'/etc/systemd/system/native-daily-network.service','utf8'),/ExecStopPost=.* recover /);
  // Import closure must work from the installed copy without repo modules.
  const control=bundle+'/control';
  for(const f of manifest.files.filter(f=>f.name.startsWith('control/')&&f.name.endsWith('.mjs'))){
    const source=fs.readFileSync(bundle+'/'+f.name,'utf8');
    for(const m of source.matchAll(/from ['"](\.[^'"]+)['"]/g))assert.ok(fs.existsSync(path.resolve(path.dirname(bundle+'/'+f.name),m[1])),`${f.name}: ${m[1]}`);
  }
  assert.ok(fs.existsSync(control+'/clean-vpn-native-tun.py'));
  assert.throws(()=>installNative({...options,apply:true}),/instance_already_present/);
  const alternate=JSON.parse(fs.readFileSync(root+'/config'));alternate.peer_ipv4='10.99.0.37';put('/config',JSON.stringify(alternate));
  installNative({...options,name:'second',apply:true});
  assert.equal(JSON.parse(fs.readFileSync(root+'/opt/clean-vpn-native/second/network.json')).peer_ipv4,'10.99.0.37');
});
