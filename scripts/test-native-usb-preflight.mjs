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
