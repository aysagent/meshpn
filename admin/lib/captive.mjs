import fs from 'node:fs';
import {isIPv4} from 'node:net';
import {need,ipv4Subnet} from './common.mjs';

export const portalAddress='192.168.7.1',portalSubnet='192.168.7.0/24';
export const portalUrl='http://192.168.7.1/#wifi';
export const portalPorts={dns:1054,http:18080};

// No WAN/TLS/DNS probe: a VPN outage must not activate Wi-Fi setup.
export function wifiSuitability(links,addresses,routes,wpa) {
 const link=links.find(l=>l.ifname==='wlan0');
 if(!link||!link.flags?.includes('UP')||!link.flags?.includes('LOWER_UP'))return{state:'offline',reason:'wifi_not_associated'};
 if(!wpa||typeof wpa.wpa_state!=='string')return{state:'unknown',reason:'wifi_status_unavailable'};
 if(wpa.wpa_state!=='COMPLETED')return{state:'offline',reason:'wifi_not_associated'};
 const usable=addresses.find(a=>a.ifname==='wlan0')?.addr_info?.some(a=>a.family==='inet'&&a.scope==='global'&&isIPv4(a.local)&&!a.local.startsWith('169.254.')&&!a.local.startsWith('127.')&&!a.local.startsWith('0.'));
 if(!usable)return{state:'offline',reason:'wifi_ipv4_pending'};
 if(!routes.some(r=>r.dev==='wlan0'&&r.dst==='default'&&(!r.type||r.type==='unicast')&&!r.flags?.includes('linkdown')))return{state:'offline',reason:'wifi_route_pending'};
 return{state:'ready',reason:'wifi_ready'};
}
export class PortalDecision {
 constructor(){this.offline=0;}
 sample(s){this.offline=s.state==='offline'?Math.min(2,this.offline+1):0;return this.offline>=2;}
}
export function readPortalState(file,now=Date.now()) {
 try {
  const st=fs.lstatSync(file);need(st.isFile()&&!(st.mode&0o022)&&st.size<2048,'portal_state');
  const s=JSON.parse(fs.readFileSync(file,'utf8'));
  need(s.kind==='meshpn-usb-captive'&&typeof s.active==='boolean'&&Number.isFinite(s.updatedAt)&&now>=s.updatedAt&&now-s.updatedAt<10000,'portal_state');
  return{active:s.active,reason:s.reason,updatedAt:s.updatedAt};
 }catch{return{active:false,reason:'portal_unavailable'};}
}

// Offline, USB-scoped synthetic resolver. Never forwards or uses OS DNS.
// TTL zero limits persistence across Wi-Fi recovery. No AAAA/HTTPS/SVCB hints.
export function portalDns(query,active) {
 if(query.length<12||query.length>1232||(query.readUInt16BE(2)&0x8000))return null;
 const flags=query.readUInt16BE(2),header=Buffer.alloc(12);query.copy(header,0,0,2);
 let end=12,nameBytes=0,type=0,klass=0,code=0;
 try{
  need(!(flags&0x7800)&&query.readUInt16BE(4)===1&&query.readUInt16BE(6)===0&&query.readUInt16BE(8)===0&&query.readUInt16BE(10)<=1,'dns_question');
  for(;;){need(end<query.length,'dns_question');const n=query[end++];if(!n)break;need(n<=63&&end+n<=query.length,'dns_question');nameBytes+=n+1;need(nameBytes<=254,'dns_question');end+=n;}
  need(nameBytes>0&&end+4<=query.length,'dns_question');type=query.readUInt16BE(end);klass=query.readUInt16BE(end+2);end+=4;
  code=!active?2:klass!==1?5:![1,28,65,64].includes(type)?5:0;
 }catch{end=12;code=1;}
 header.writeUInt16BE(0x8000|(flags&0x0100)|code,2);
 if(end===12)return header;
 header.writeUInt16BE(1,4);
 const parts=[header,query.subarray(12,end)];
 if(!code&&type===1){header.writeUInt16BE(1,6);parts.push(Buffer.from([0xc0,0x0c,0,1,0,1,0,0,0,0,0,4,192,168,7,1]));}
 return Buffer.concat(parts);
}
export function portalPeer(ip){return ipv4Subnet(ip,portalSubnet)&&ip!==portalAddress;}
