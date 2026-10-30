// Explicit projection: never serialize raw configs, jobs/results or credentials.
import {publicEngineDiagnostics} from './engine-diagnostics.mjs';
const scalar=v=>typeof v==='boolean'||(typeof v==='number'&&Number.isFinite(v))||(typeof v==='string'&&v.length<=512);
const pick=(o,keys)=>Object.fromEntries(keys.filter(k=>scalar(o?.[k])).map(k=>[k,o[k]]));
const list=(v,n,fn)=>Array.isArray(v)?v.slice(0,n).map(fn):[];
export function diagnosticExport(status={},settings={}){
 const m=status.metrics??{},c=status.certificates??{};
 return{
  schema:1,kind:'meshpn-admin-diagnostic',timestamp:new Date().toISOString(),
  privacy:'Includes endpoint addresses, interface names, profile names and public certificate fingerprints. No credentials, raw configurations, logs, captures, SSIDs or job results.',
  scope:'point-in-time admin state; no probes, no DNS leak or transport indistinguishability claim',
  metrics:{...pick(m,['time','timezone','uptimeSeconds']),memory:pick(m.memory,['MemTotal','MemAvailable','SwapTotal','SwapFree']),cpu:list(m.cpu,256,x=>pick(x,['core','percent'])),temperatures:list(m.temperatures,32,x=>pick(x,['celsius'])),network:list(m.network,64,x=>pick(x,['interface','rxBytes','txBytes','rxDropped','txDropped']))},
  vpn:{...pick(status.vpn,['ActiveState','SubState','UnitFileState','MainPID']),settings:pick(settings.vpn,['role','address','port','serverName','sni','profile','dns','transport','nativeManaged'])},
  network:pick(status.network,['ActiveState','SubState','UnitFileState','MainPID']),
  engineDiagnostics:publicEngineDiagnostics(status.engineDiagnostics),
  guard:pick(status.guard,['active']),wifi:pick(status.wifi,['wpa_state']),
  dns:pick(settings.dns,['mode','upstreams','integrationManaged']),
  capabilities:pick(status.capabilities,['nativeManaged','networkOwner','containerManaged','role','clients','wifi','guardToggle','hostnameChange','observer','profileImport','vpnSettings','routingRules','dnsUpstreamConfig']),
  certificates:{...pick(c,['scope','status','remoteLeafObserved','clock','warningDays','verification','reason']),certificates:list(c.certificates,32,x=>pick(x,['index','ca','fingerprint256','validFrom','validTo','daysRemaining','state']))},
  jobs:list(status.jobs,32,x=>pick(x,['id','kind','status','started','finished'])),
 };
}
