import test from 'node:test';
import assert from 'node:assert/strict';
import {inspectNativeUsb,requireNativeUsb} from './lib/native-usb-preflight.mjs';
function fixture(){
 const script='/usr/local/bin/usb-gadget-start.sh';
 const usb={ifname:'usb0',address:'02:00:00:00:00:02',flags:['UP'],addr_info:[{family:'inet',local:'192.168.7.1',prefixlen:24}]};
 const units={
  'usb-gadget.service':{LoadState:'loaded',ActiveState:'active',UnitFileState:'enabled',After:'network.target dnsmasq.service',ExecStart:`{ path=${script} ; argv[]=${script} ; }`},
  'dnsmasq.service':{LoadState:'loaded',ActiveState:'active',UnitFileState:'enabled',MainPID:'42'}
 };
 const files={
  '/proc/1/comm':'systemd\n',[script]:'known tested script',
  '/sys/kernel/config/usb_gadget/g1/functions/ecm.usb0/ifname':'usb0\n',
  '/sys/kernel/config/usb_gadget/g1/UDC':'fcc00000.usb\n',
  '/proc/42/net/udp':'header\n0: 00000000:0043 00000000:0000 07 0 0 0 0 0 123\n'
 };
 const links={'/proc/self/ns/net':'net:[1]','/proc/1/ns/net':'net:[1]','/proc/42/fd/3':'socket:[123]'};
 const io={readFileSync:p=>{assert.ok(p in files,p);return files[p];},readlinkSync:p=>{assert.ok(p in links,p);return links[p];},readdirSync:p=>{assert.equal(p,'/proc/42/fd');return ['3'];},lstatSync:p=>{assert.equal(p,script);return {isFile:()=>true,isSymbolicLink:()=>false,uid:0,mode:0o755};}};
 const deps={platform:'linux',io,digest:bytes=>{assert.equal(bytes,'known tested script');return 'c0d55c1d8c765084cd674b013e90075b2558ed7adee1e11e42f64c541de7b94b';},run:(file,args)=>{
  if(file==='/usr/sbin/ip')return JSON.stringify([usb]);
  assert.equal(file,'/usr/bin/systemctl');assert.equal(args[0],'show');return Object.entries(units[args[1]]).map(([k,v])=>k+'='+v).join('\n');
 }};
 return {deps,usb,units,files,links};
}
test('known live profile passes without writing or probing the network',()=>{
 const {deps}=fixture();const r=inspectNativeUsb(deps);assert.equal(r.status,'passed');assert.equal(r.systemSettingsChanged,false);assert.equal(r.networkProbesSent,0);
});
for(const [name,change,reason] of [
 ['missing address',f=>f.usb.addr_info=[],'usb_address_profile_required'],
 ['boot ordering missing',f=>f.units['usb-gadget.service'].After='network.target','usb_dhcp_before_gadget_required'],
 ['DHCP disabled at boot',f=>f.units['dnsmasq.service'].UnitFileState='disabled','usb_dhcp_boot_service_required'],
 ['unrelated UDP67 socket',f=>f.links['/proc/42/fd/3']='socket:[999]','usb_dhcp_socket_required'],
 ['DHCP bound to other subnet',f=>f.files['/proc/42/net/udp']=f.files['/proc/42/net/udp'].replace('00000000:0043','0100007F:0043'),'usb_dhcp_socket_required'],
 ['unknown gadget script',f=>f.deps.digest=()=> 'different','usb_gadget_script_review_required'],
 ['container network namespace',f=>f.links['/proc/self/ns/net']='net:[2]','usb_host_namespace_required'],
 ['unbound gadget',f=>f.files['/sys/kernel/config/usb_gadget/g1/UDC']='\n','usb_gadget_bound_required'],
 ['incomplete inspection',f=>f.deps.io.readdirSync=()=>{throw Error('EACCES');},'usb_inspection_incomplete'],
])test(name+' refuses target installation',()=>{const f=fixture();change(f);const r=inspectNativeUsb(f.deps);assert.equal(r.status,'refused');assert.ok(r.reasons.includes(reason));assert.throws(()=>requireNativeUsb({root:'/',hostProfile:'profile'},()=>r),e=>e.message==='native_usb_preflight_failed'&&e.usbPreflight===r);});
test('staging and non-USB installations do not inspect the build machine',()=>{
 const no=()=>{throw Error('must_not_probe');};assert.equal(requireNativeUsb({root:'/stage',hostProfile:'profile'},no).status,'required-on-target');assert.equal(requireNativeUsb({root:'/'},no),undefined);
});
test('non Linux refuses explicitly',()=>{assert.deepEqual(inspectNativeUsb({platform:'darwin'}).reasons,['usb_linux_required']);});

function networkdFixture(){
 const files={'/proc/1/comm':'systemd','/usr/local/libexec/armbian-usb-multi-gadget':'vendor script',
 '/sys/kernel/config/usb_gadget/armbian_multi_gadget/UDC':'4100000.udc-controller','/sys/kernel/config/usb_gadget/armbian_multi_gadget/functions/ncm.usb0/ifname':'usb0',
 '/etc/systemd/network/80-armbian-usb-gadget.network':'[Match]\nName=usb0\n[Network]\nAddress=192.168.8.1/24\nDHCPServer=yes\nConfigureWithoutCarrier=yes\n[DHCPServer]\nEmitRouter=yes\nEmitDNS=yes\nDNS=192.168.8.1\n',
 '/etc/systemd/resolved.conf.d/80-armbian-usb-gadget.conf':'[Resolve]\nDNSStubListenerExtra=192.168.8.1\n',
 '/proc/42/net/udp':'header\n0: 00000000:0043 0 0 0 0 0 0 0 123\n',
 '/proc/43/net/udp':'header\n0: 0108A8C0:0035 0 0 0 0 0 0 0 124\n'};
 const units=Object.fromEntries(['armbian-usb-gadget.service','systemd-networkd.service','systemd-resolved.service'].map(n=>[n,{LoadState:'loaded',ActiveState:'active',UnitFileState:'enabled'}]));
 Object.assign(units['armbian-usb-gadget.service'],{Before:'systemd-networkd.service',ExecStart:'{ path=/usr/local/libexec/armbian-usb-multi-gadget ; }'});units['systemd-networkd.service'].MainPID='42';units['systemd-resolved.service'].MainPID='43';
 const deps={profile:{usb_backend:'networkd',usb_address:'192.168.8.1',uplink:'auto'},platform:'linux',
 io:{readFileSync:p=>{assert.ok(p in files,p);return files[p];},lstatSync:()=>({isFile:()=>true,isSymbolicLink:()=>false,uid:0,mode:0o644}),readlinkSync:p=>p.includes('/fd/')?'socket:['+(p.includes('/42/')?'123':'124')+']':'net:[1]',readdirSync:p=>p.endsWith('/fd')?['3']:[]},
 run:(f,a)=>f.endsWith('/ip')?JSON.stringify([{flags:['UP'],addr_info:[{family:'inet',local:'192.168.8.1',prefixlen:24}]}]):f.endsWith('/networkctl')?'Network File: /etc/systemd/network/80-armbian-usb-gadget.network':Object.entries(units[a[1]]).map(([k,v])=>k+'='+v).join('\n')};
 return{deps,files,units};
}
test('existing networkd gadget validates address, DHCP owner and USB DNS listener read-only',()=>{const r=inspectNativeUsb(networkdFixture().deps);assert.equal(r.status,'passed',JSON.stringify(r));assert.equal(r.networkProbesSent,0);});
for(const [name,change]of[
 ['wrong DNS server',f=>f.files['/etc/systemd/network/80-armbian-usb-gadget.network']=f.files['/etc/systemd/network/80-armbian-usb-gadget.network'].replace('DNS=192.168.8.1','DNS=1.1.1.1')],
 ['wrong DHCP inode',f=>f.files['/proc/42/net/udp']=f.files['/proc/42/net/udp'].replace('123','999')],
 ['disabled resolver',f=>f.units['systemd-resolved.service'].UnitFileState='disabled'],
 ['conflicting drop-in',f=>f.deps.io.readdirSync=p=>p.endsWith('/fd')?['3']:['override.conf']],
 ['wrong config owner',f=>f.deps.io.lstatSync=()=>({isFile:()=>true,isSymbolicLink:()=>false,uid:1000,mode:0o644})],
 ['missing USB carrier config',f=>f.files['/etc/systemd/network/80-armbian-usb-gadget.network']=f.files['/etc/systemd/network/80-armbian-usb-gadget.network'].replace('ConfigureWithoutCarrier=yes','ConfigureWithoutCarrier=no')],
])test('networkd refuses '+name,()=>{const f=networkdFixture();change(f);assert.equal(inspectNativeUsb(f.deps).status,'refused');});
