/** Read-only check for the existing, fixed Radxa --host-profile. No DHCP probes. */
import fs from 'node:fs';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const supportedScript = 'c0d55c1d8c765084cd674b013e90075b2558ed7adee1e11e42f64c541de7b94b';
const limits = ['point-in-time-not-cold-boot-proof','no-DHCP-offer-or-client-lease-probe','no-effective-dnsmasq-config-validation','no-DNS-or-internet-probe','fixed-radxa-host-profile-only'];
const command = (file,args) => execFileSync(file,args,{encoding:'utf8',timeout:3000,maxBuffer:65536});
export function inspectNativeUsb({run=command,io=fs,platform=process.platform,digest=bytes=>createHash('sha256').update(bytes).digest('hex')}={}) {
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
    require(digest(io.readFileSync(script))===supportedScript,'usb_gadget_script_review_required');
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
export function requireNativeUsb({root,hostProfile}, inspect=inspectNativeUsb) {
  if(!hostProfile)return undefined;
  if(root!=='/')return {status:'required-on-target',scope:'staging-root-not-live-host',systemSettingsChanged:false};
  const report=inspect();
  if(report.status!=='passed') {
    const error=new Error('native_usb_preflight_failed');error.usbPreflight=report;throw error;
  }
  return report;
}
