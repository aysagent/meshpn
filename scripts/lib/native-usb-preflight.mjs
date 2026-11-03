/** Read-only check for the existing, fixed Radxa --host-profile. No DHCP probes. */
import fs from 'node:fs';
import {nativeHostProfile} from './native-host-profile.mjs';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const freshScript = createHash('sha256').update(fs.readFileSync(new URL('../usb/gadget-start.sh',import.meta.url))).digest('hex');
const supportedScript = 'c0d55c1d8c765084cd674b013e90075b2558ed7adee1e11e42f64c541de7b94b';
const limits = ['point-in-time-not-cold-boot-proof','no-DHCP-offer-or-client-lease-probe','no-effective-dnsmasq-config-validation','no-DNS-or-internet-probe','fixed-radxa-host-profile-only'];
const command = (file,args) => execFileSync(file,args,{encoding:'utf8',timeout:3000,maxBuffer:65536});
export function inspectNativeUsb({run=command,io=fs,platform=process.platform,profile={},digest=bytes=>createHash('sha256').update(bytes).digest('hex')}={}) {
  if(profile.usb_backend==='networkd')return inspectNetworkdUsb({run,io,platform,profile});
  const result={schema:1,kind:'clean-vpn-native-usb-preflight',status:'refused',systemSettingsChanged:false,networkProbesSent:0,checks:{},reasons:[],limitations:limits};
  const require=(ok,code)=>{result.checks[code]=Boolean(ok);if(!ok)result.reasons.push(code);};
  const props=unit=>Object.fromEntries(run('/usr/bin/systemctl',['show',unit,'-p','LoadState','-p','ActiveState','-p','UnitFileState','-p','MainPID','-p','After','-p','ExecStart']).trim().split('\n').map(line=>{const i=line.indexOf('=');if(i<1)throw Error('properties');return[line.slice(0,i),line.slice(i+1)];}));
  try {
    require(platform==='linux','usb_linux_required');
    if(platform!=='linux')return result;
    require(io.readFileSync('/proc/1/comm','utf8').trim()==='systemd','usb_systemd_required');
    require(io.readlinkSync('/proc/self/ns/net')===io.readlinkSync('/proc/1/ns/net'),'usb_host_namespace_required');
    const links=JSON.parse(run('/usr/sbin/ip',['-j','address','show','dev','usb0']));
    const usb=links.length===1?links[0]:null;
    require(usb?.ifname==='usb0'&&usb.address==='02:00:00:00:00:02'&&usb.flags?.includes('UP')&&
      JSON.stringify(usb.addr_info?.filter(a=>a.family==='inet').map(a=>[a.local,a.prefixlen]))===JSON.stringify([['192.168.7.1',24]]),'usb_address_profile_required');
    const gadget=props('usb-gadget.service'),dns=props('dnsmasq.service');
    require(gadget.LoadState==='loaded'&&gadget.ActiveState==='active'&&gadget.UnitFileState==='enabled','usb_gadget_boot_service_required');
    require(dns.LoadState==='loaded'&&dns.ActiveState==='active'&&dns.UnitFileState==='enabled','usb_dhcp_boot_service_required');
    require(gadget.After?.split(/\s+/).includes('dnsmasq.service'),'usb_dhcp_before_gadget_required');
    const script='/usr/local/bin/usb-gadget-start.sh';
    require(gadget.ExecStart?.includes('path='+script+' ;'),'usb_gadget_command_review_required');
    const stat=io.lstatSync(script);
    require(stat.isFile()&&!stat.isSymbolicLink()&&stat.uid===0&&!(stat.mode&0o022),'usb_gadget_script_ownership_required');
    require([supportedScript,freshScript].includes(digest(io.readFileSync(script))),'usb_gadget_script_review_required');
    require(io.readFileSync('/sys/kernel/config/usb_gadget/g1/functions/ecm.usb0/ifname','utf8').trim()==='usb0'&&
      io.readFileSync('/sys/kernel/config/usb_gadget/g1/UDC','utf8').trim()!=='','usb_gadget_bound_required');
    let socket=false;
    if(/^[1-9][0-9]*$/.test(dns.MainPID??'')) {
      const base='/proc/'+dns.MainPID,owned=new Set();
      for(const fd of io.readdirSync(base+'/fd')) {
        if(!/^\d+$/.test(fd))continue;
        try{owned.add(io.readlinkSync(base+'/fd/'+fd));}catch(e){if(e.code!=='ENOENT')throw e;}
      }
      socket=io.readFileSync(base+'/net/udp','utf8').split('\n').slice(1).some(line=>{
        const fields=line.trim().split(/\s+/);
        return ['00000000:0043','0107A8C0:0043'].includes(fields[1])&&owned.has('socket:['+fields[9]+']');
      });
      require(props('dnsmasq.service').MainPID===dns.MainPID,'usb_dhcp_process_changed');
    }
    require(socket,'usb_dhcp_socket_required');
  } catch {result.reasons.push('usb_inspection_incomplete');}
  result.status=result.reasons.length?'refused':'passed';
  return result;
}
export function requireNativeUsb({root,hostProfile,profile}, inspect=inspectNativeUsb) {
  if(!hostProfile)return undefined;
  if(root!=='/')return {status:'required-on-target',scope:'staging-root-not-live-host',systemSettingsChanged:false};
  const report=inspect({profile});
  if(report.status!=='passed') {
    const error=new Error('native_usb_preflight_failed');error.usbPreflight=report;throw error;
  }
  return report;
}

// Existing Armbian gadget: preserve the vendor USB/DHCP/resolver services.
// This is deliberately a narrow, explicit profile, not a general networkd installer.
export function inspectNetworkdUsb({run=command,io=fs,platform=process.platform,profile={}}={}){
 const result={schema:1,kind:'clean-vpn-native-usb-preflight',backend:'networkd',status:'refused',systemSettingsChanged:false,networkProbesSent:0,checks:{},reasons:[],limitations:['point-in-time-not-cold-boot-proof','no-DHCP-offer-or-client-lease-probe','no-DNS-or-internet-probe','existing-armbian-networkd-profile-only']};
 const require=(ok,code)=>{result.checks[code]=Boolean(ok);if(!ok)result.reasons.push(code);};
 const props=unit=>Object.fromEntries(run('/usr/bin/systemctl',['show',unit,'-p','LoadState','-p','ActiveState','-p','UnitFileState','-p','MainPID','-p','Before','-p','ExecStart']).trim().split('\n').map(l=>{const i=l.indexOf('=');return[l.slice(0,i),l.slice(i+1)];}));
 const owned=p=>{const s=io.lstatSync(p);require(s.isFile()&&!s.isSymbolicLink()&&s.uid===0&&!(s.mode&0o022),'usb_owned_config_required');return io.readFileSync(p,'utf8');};
 try{
  require(platform==='linux','usb_linux_required');if(platform!=='linux')return result;
  const {address}=nativeHostProfile(profile);require(address==='192.168.8.1','usb_networkd_address_required');
  require(io.readFileSync('/proc/1/comm','utf8').trim()==='systemd','usb_systemd_required');
  require(io.readlinkSync('/proc/self/ns/net')===io.readlinkSync('/proc/1/ns/net'),'usb_host_namespace_required');
  const links=JSON.parse(run('/usr/sbin/ip',['-j','address','show','dev','usb0']));
  require(links.length===1&&links[0].flags?.includes('UP')&&JSON.stringify(links[0].addr_info?.filter(a=>a.family==='inet').map(a=>[a.local,a.prefixlen]))===JSON.stringify([[address,24]]),'usb_address_profile_required');
  const gadget=props('armbian-usb-gadget.service'),dhcp=props('systemd-networkd.service'),dns=props('systemd-resolved.service');
  for(const [unit,label]of [[gadget,'gadget'],[dhcp,'dhcp'],[dns,'dns']])require(unit.LoadState==='loaded'&&unit.ActiveState==='active'&&unit.UnitFileState==='enabled','usb_'+label+'_boot_service_required');
  require(gadget.Before?.split(/\s+/).includes('systemd-networkd.service'),'usb_networkd_order_required');
  const script='/usr/local/libexec/armbian-usb-multi-gadget';owned(script);require(gadget.ExecStart?.includes('path='+script+' ;'),'usb_gadget_command_review_required');
  const base='/sys/kernel/config/usb_gadget/armbian_multi_gadget';
  require(io.readFileSync(base+'/UDC','utf8').trim()!==''&&io.readFileSync(base+'/functions/ncm.usb0/ifname','utf8').trim()==='usb0','usb_gadget_bound_required');
  const config='/etc/systemd/network/80-armbian-usb-gadget.network',text=owned(config);
  const entries=new Map();let section='';for(const line of text.split('\n').map(l=>l.trim()).filter(l=>l&&!l.startsWith('#')&&!l.startsWith(';'))){if(/^\[.*\]$/.test(line)){section=line.slice(1,-1);continue;}const i=line.indexOf('='),k=section+'.'+line.slice(0,i);require(i>0&&!entries.has(k),'usb_networkd_config_unambiguous');entries.set(k,line.slice(i+1));}
  for(const [k,v]of Object.entries({'Match.Name':'usb0','Network.Address':address+'/24','Network.DHCPServer':'yes','Network.ConfigureWithoutCarrier':'yes','DHCPServer.EmitRouter':'yes','DHCPServer.EmitDNS':'yes','DHCPServer.DNS':address}))require(entries.get(k)===v,'usb_networkd_'+k.replaceAll('.','_'));
  require(run('/usr/bin/networkctl',['status','usb0','--no-pager','--lines=0']).includes(config),'usb_networkd_effective_file_required');
  for(const dir of ['/etc','/run','/usr/lib'].map(d=>d+'/systemd/network/80-armbian-usb-gadget.network.d')){try{require(io.readdirSync(dir).filter(n=>n.endsWith('.conf')).length===0,'usb_networkd_dropin_review_required');}catch(e){if(e.code!=='ENOENT')throw e;}}
  const dnsConfig=owned('/etc/systemd/resolved.conf.d/80-armbian-usb-gadget.conf');require(/^DNSStubListenerExtra=192\.168\.8\.1$/m.test(dnsConfig),'usb_dns_listener_config_required');
  const ownsUdp=(unit,hex)=>{if(!/^[1-9][0-9]*$/.test(unit.MainPID??''))return false;const proc='/proc/'+unit.MainPID,owned=new Set(io.readdirSync(proc+'/fd').filter(n=>/^\d+$/.test(n)).map(n=>{try{return io.readlinkSync(proc+'/fd/'+n);}catch(e){if(e.code==='ENOENT')return '';throw e;}}));return io.readFileSync(proc+'/net/udp','utf8').split('\n').slice(1).some(l=>{const f=l.trim().split(/\s+/);return (f[1]===hex||(hex.endsWith(':0043')&&f[1]==='00000000:0043'))&&owned.has('socket:['+f[9]+']');});};
  require(ownsUdp(dhcp,'0108A8C0:0043'),'usb_dhcp_socket_required');require(ownsUdp(dns,'0108A8C0:0035'),'usb_dns_socket_required');
  require(props('systemd-networkd.service').MainPID===dhcp.MainPID&&props('systemd-resolved.service').MainPID===dns.MainPID,'usb_provider_changed');
 }catch{result.reasons.push('usb_inspection_incomplete');}
 result.status=result.reasons.length?'refused':'passed';return result;
}
