import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {setupOptions,NativeSetup} from './lib/native-setup.mjs';
const temp=t=>{const p=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-setup-')));t.after(()=>fs.rmSync(p,{recursive:true,force:true}));return p;};
test('small CLI: role, transport, bundle and admin constraints; no shell fragments',()=>{
 const e=setupOptions('install',['--role=exit','--endpoint=192.0.2.1']);assert.equal(e.type,'combo-tls');assert.equal(e.port,'443');assert.equal(e.clients,'3');
 assert.equal(setupOptions('install',['--role=client','--bundle=/root/client.json','--admin-ui'])['admin-ui'],true);
 for(const args of [['--role=exit'],['--role=exit','--endpoint=example.org'],['--role=exit','--endpoint=192.0.2.1','--admin-ui'],['--role=client'],['--role=client','--bundle=/tmp/x','--config=/tmp/y'],['--role=exit','--endpoint=192.0.2.1','--name=a;id'],['--role=exit','--endpoint=192.0.2.1','--port=0'],['--role=exit','--endpoint=192.0.2.1','--role=exit']])assert.throws(()=>setupOptions('install',args));
 assert.equal(setupOptions('uninstall',['--role=client']).action,'uninstall');
 assert.equal(setupOptions('install',['--role=client','--check']).action,'check');
});
test('plan does not run commands, create files or issue credentials',async t=>{
 const root=temp(t),o=setupOptions('install',['--role=exit','--endpoint=192.0.2.1','--plan']);const n=new NativeSetup(o,{root,run:()=>{throw Error('unexpected command');}});
 assert.equal((await n.execute()).networkChanged,false);assert.deepEqual(fs.readdirSync(root),[]);
});
function owner(t){const root=temp(t),o=setupOptions('install',['--role=exit','--endpoint=192.0.2.1']);const calls=[];let value='0';const n=new NativeSetup(o,{root,run:(f,a)=>{calls.push([f,a]);if(f.endsWith('/sysctl')){if(a[0]==='-n')return value;value=a[1].split('=')[1];return '';}throw Error('unexpected command');}});fs.mkdirSync(n.base,{recursive:true,mode:0o700});n.state={version:1,files:[],services:{},forward:false};n.save();return{n,root,calls,value:()=>value,set:v=>{value=v;}};}
test('owned file intent restores exact bytes/mode; foreign collision and drift refused',t=>{
 const {n,root}=owner(t),p='/etc/example.conf';fs.mkdirSync(root+'/etc');fs.writeFileSync(root+p,'original',{mode:0o600});
 assert.throws(()=>n.file(p,'after'),/file_collision/);assert.equal(fs.readFileSync(root+p,'utf8'),'original');
 n.file(p,'after',0o644,{replace:true});assert.equal(n.state.files[0].before,Buffer.from('original').toString('base64'));
 fs.writeFileSync(root+p,'third-party');assert.throws(()=>n.restoreFile(n.state.files[0]),/owned_file_changed/);assert.equal(fs.readFileSync(root+p,'utf8'),'third-party');
 fs.writeFileSync(root+p,'after');n.restoreFile(n.state.files[0]);assert.equal(fs.readFileSync(root+p,'utf8'),'original');assert.equal(fs.statSync(root+p).mode&0o777,0o600);
 n.restoreFile(n.state.files[0]);
});
test('symlink destinations never followed or overwritten',t=>{
 const {n,root}=owner(t);fs.mkdirSync(root+'/etc');fs.writeFileSync(root+'/sentinel','sentinel');fs.symlinkSync(root+'/sentinel',root+'/etc/link');assert.throws(()=>n.file('/etc/link','bad',0o644,{replace:true}),/unsafe_owned_file/);assert.equal(fs.readFileSync(root+'/sentinel','utf8'),'sentinel');
});
test('forwarding is enabled once, shared by instances, restored after last owner',t=>{
 const {n,root,value}=owner(t);n.forward(true);assert.equal(value(),'1');const second=new NativeSetup({...n.o,name:'second'},{root,run:n.run});fs.mkdirSync(second.base);second.state={files:[],services:{},forward:false};second.save();second.forward(true);
 n.forward(false);assert.equal(value(),'1');second.forward(false);assert.equal(value(),'0');assert.equal(fs.existsSync(root+'/etc/sysctl.d/90-clean-vpn-native-forward.conf'),false);
});
test('forwarding refuses existing foreign persistence file before changing sysctl',t=>{
 const {n,root,calls}=owner(t);fs.mkdirSync(root+'/etc/sysctl.d',{recursive:true});fs.writeFileSync(root+'/etc/sysctl.d/90-clean-vpn-native-forward.conf','foreign');assert.throws(()=>n.forward(true),/forwarding_file_collision/);assert.equal(calls.length,0);
});
test('forwarding drift is retained rather than overwritten by uninstall',t=>{
 const {n,root,set}=owner(t);n.forward(true);set('2');assert.throws(()=>n.forward(false),/forwarding_changed/);assert.equal(fs.existsSync(root+'/var/lib/clean-vpn/setup/forwarding.json'),true);
});
test('forwarding release recovers publication before instance flag was saved',t=>{
 const {n,value}=owner(t);n.forward(true);n.state.forward=false;n.save();n.forward(false);assert.equal(value(),'0');
});
test('corrupt forwarding ownership journal is refused before sysctl mutation',t=>{
 const {n,root,calls}=owner(t);fs.writeFileSync(root+'/var/lib/clean-vpn/setup/forwarding.json',JSON.stringify({version:1,original:'0',owners:['exit','exit']}));
 assert.throws(()=>n.forward(true),/forwarding_journal_invalid/);assert.equal(calls.length,0);
});

test('explicit existing networkd profile preserves DHCP and gadget instead of creating dnsmasq',t=>{
 const root=temp(t),o=setupOptions('install',['--role=client','--bundle=/root/client.json','--usb-backend=networkd','--usb-address=192.168.8.1','--uplink=auto']);
 let inspections=0;const n=new NativeSetup(o,{root,run:()=>{throw Error('must not mutate existing USB');},usb:({profile})=>{assert.equal(profile.usb_address,'192.168.8.1');assert.equal(profile.usb_backend,'networkd');inspections++;return{status:'passed'};}});
 n.usbSetup();assert.equal(inspections,1);assert.deepEqual(fs.readdirSync(root),[]);
 assert.throws(()=>setupOptions('install',['--role=client','--bundle=/root/x','--usb-address=192.168.8.1']),/usb_networkd_required/);
});

test('Armbian USB firewall is ordered before guard without basic/networkd boot cycle; owned and reversible',t=>{
 const {n,root}=owner(t);n.prop=(unit,key)=>{assert.equal(unit,'armbian-usb-gadget-firewall.service');assert.equal(key,'LoadState');return 'loaded';};
 assert.equal(n.networkdUsbOrder(),true);assert.equal(n.networkdUsbOrder(),false);
 const vendor='/etc/systemd/system/armbian-usb-gadget-firewall.service.d/90-clean-vpn-order.conf',guard='/etc/systemd/system/clean-vpn-killswitch.service.d/20-armbian-usb.conf';
 assert.match(fs.readFileSync(root+vendor,'utf8'),/DefaultDependencies=no\nAfter=local-fs.target armbian-usb-gadget.service\nBefore=clean-vpn-killswitch.service shutdown.target/);
 assert.match(fs.readFileSync(root+guard,'utf8'),/Wants=armbian-usb-gadget-firewall.service\nAfter=armbian-usb-gadget-firewall.service/);
 for(const f of n.state.files)n.restoreFile(f);assert.equal(fs.existsSync(root+vendor),false);assert.equal(fs.existsSync(root+guard),false);
});
