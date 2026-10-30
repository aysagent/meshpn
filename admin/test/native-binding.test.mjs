import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {installNative} from '../../scripts/lib/native-install.mjs';
import {nativeAdminBinding} from '../lib/native-binding.mjs';
for(const combo of [false,true])test(`admin binds a fresh ${combo?'combo':'boring'} standalone installation`,t=>{
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'admin-native-')));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const put=(p,b,mode=0o600)=>fs.writeFileSync(root+p,b,{mode});
 fs.mkdirSync(root+'/opt');fs.mkdirSync(root+'/etc/systemd/system',{recursive:true});
 put('/etc/systemd/system/clean-vpn-killswitch.service','[Service]\nType=oneshot\nExecStart=/bin/true\n',0o644);
 put('/engine',`#!/bin/sh\nif [ "$1" = --capabilities ]; then echo '{"engine":"clean-vpn-native-m1","packet_ipc":false,"service_mode":true,"dns_socket_mark":"0x43564e","experimental_transports":{"combo-tls":{"site_provisioning":true}}}'; fi\n`,0o755);
 put('/ca','fixture');put('/psk',Buffer.alloc(32,1));
 const packet={version:1,role:'client',address:'192.0.2.1',port:443,tun:'tun0',dns:true,ca:root+'/ca',secret_path:root+'/psk'};
 put('/relay.psk',Buffer.alloc(32,2));
 put('/config',JSON.stringify(combo?{version:1,transport:'combo-tls',role:'client',boring:packet,transparent:{version:1,transport:'transparent-tls',role:'client',public_name:'relay.example',listen:{ipv4:'0.0.0.0',port:14443},exit:{ipv4:packet.address,port:packet.port},secret_path:root+'/relay.psk',destination_policy:{mode:'public-https',deny_ipv4:[]}}}:packet));
 put('/host',JSON.stringify({version:1,guard_unit:'clean-vpn-killswitch.service',guard_script:'/usr/local/bin/clean-vpn-killswitch.sh'}));
 installNative({root,name:'daily',binary:root+'/engine',config:root+'/config',hostProfile:root+'/host',apply:true});
 const b=nativeAdminBinding('daily',{root});assert.equal(b.nativeManaged,true);assert.equal(b.networkUnit,'native-daily-network.service');
 assert.equal(b.vpnConfig,'/opt/clean-vpn-native/daily/config.json');assert.equal((combo?b.config.boring:b.config).address,'192.0.2.1');
 if(combo){const file=root+'/opt/clean-vpn-native/daily/config.json',config=JSON.parse(fs.readFileSync(file));config.transparent.exit.port=444;fs.writeFileSync(file,JSON.stringify(config));assert.throws(()=>nativeAdminBinding('daily',{root}),/native_combo_binding/);config.transparent.exit.port=443;fs.writeFileSync(file,JSON.stringify(config));}
 for(const name of ['../daily','daily/x',''])assert.throws(()=>nativeAdminBinding(name,{root}),/native_install_name/);
 const network=root+'/etc/systemd/system/native-daily-network.service';fs.appendFileSync(network,'# changed');
 assert.throws(()=>nativeAdminBinding('daily',{root}),/native_unit_changed/);
});
