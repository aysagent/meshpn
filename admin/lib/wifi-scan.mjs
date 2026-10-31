import {decodeWifiSsid,validWifiSsid} from './wifi-ssid.mjs';

// A remembered name alone cannot identify an anonymous BSSID. Keep saved but
// unseen networks selectable without claiming they were observed in this scan.
export function wifiScanNetworks(output,profiles=[]){
 const saved=[...profiles].sort((a,b)=>b.priority-a.priority),seen=new Set();
 const rows=output.split(/\r?\n/).slice(1,129).flatMap(line=>{
  const [bssid,frequency,signal,security,...name]=line.split('\t');
  const ssid=decodeWifiSsid(name.join('\t'));if(ssid===null)return[];
  seen.add(ssid);const profile=saved.find(p=>p.ssid===ssid);
  return[{bssid,frequency:Number(frequency),signal:Number(signal),security,ssid,
   source:'scan',observed:true,...(profile?{savedId:profile.id}:{})}];
 });
 for(const p of saved){
  if(!validWifiSsid(p.ssid)||seen.has(p.ssid))continue;
  seen.add(p.ssid);
  rows.push({ssid:p.ssid,security:p.security,savedId:p.id,source:'saved',observed:false,
   signal:null,frequency:null,bssid:null});
 }
 return rows;
}
