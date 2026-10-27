#!/usr/bin/env node
// One bounded, read-only report for a future boring-tls pilot. No DNS probes.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import { createHash, X509Certificate } from 'node:crypto';
import { validatePreflightConfig } from './lib/native-runtime-preflight-config.mjs';
import { validateGatewayConfig } from './lib/native-runtime-gateway-plan.mjs';
const {values:v}=parseArgs({options:{help:{type:'boolean'},...Object.fromEntries(['binary','config','gateway-config','unit','scope'].map(k=>[k,{type:'string'}]))}});
if(v.help){console.log('Usage: sudo node scripts/clean-vpn-native-runtime-preflight.mjs --binary=/absolute/clean-vpn-engine --config=/absolute/engine.json [--gateway-config=/absolute/gateway.json] [--unit=cvpn-client.service] [--scope=isolated-runtime|existing-host]\nDefault isolated-runtime requires its own cvpn0 configuration. existing-host inventories a native boring-tls config without claiming ownership of host routes/DNS.\nRead-only Linux inventory + offline native config check. No DNS/network probes, no service/route/firewall changes. Output includes IPs, paths and DNS domains; never secret bytes, process argv or journals. Config paths must be valid in the namespace where this runs.');process.exit(0);}
const report={schema:1,kind:'native-runtime-preflight',timestamp:new Date().toISOString(),systemSettingsChanged:false,dnsQueriesSent:0,
  runtime:{platform:process.platform,arch:process.arch,node:process.version,uid:process.getuid?.()},checks:{},issues:[],
  limitations:['inventory-not-authorization-to-activate','no-network-or-tunnel-health-probes','no-effective-dnsmasq-or-network-manager-config','no-early-boot-leak-proof','no-physical-power-loss-test']};
const run=(bin,args)=>{
  try{return {status:'ok',stdout:execFileSync(bin,args,{encoding:'utf8',timeout:3000,killSignal:'SIGKILL',maxBuffer:256*1024,stdio:['ignore','pipe','pipe']}).trim()};}
  catch(e){return {status:'unavailable',code:typeof e.status==='number'?e.status:e.code??'failed'};}
};
const file=(p,limit)=>{assert.ok(path.isAbsolute(p));const s=fs.lstatSync(p);assert.ok(s.isFile()&&s.size<=limit,'regular_bounded_file_required');return {bytes:fs.readFileSync(p),uid:s.uid,mode:(s.mode&0o777).toString(8)};};
try{
  const flags=process.argv.slice(2).filter(a=>a.startsWith('--')).map(a=>a.split('=')[0]);assert.equal(flags.length,new Set(flags).size);
  assert.equal(process.platform,'linux','linux_required');
  const source=file(v.config,32768),c=JSON.parse(source.bytes);
  report.scope=v.scope??'isolated-runtime';validatePreflightConfig(c,report.scope);
  if(report.scope==='existing-host')report.limitations.push('existing-host-routing-dns-ownership-not-validated');
  const binary=file(v.binary,128*1024*1024);
  report.engine={role:c.role,transport:'boring-tls',endpoint:c.address,port:c.port,tun:c.tun,peer:c.peer_ipv4??null,
    binarySha256:createHash('sha256').update(binary.bytes).digest('hex'),configMode:source.mode,configUid:source.uid};
  const check=run(v.binary,['--check-config',v.config]);report.checks.nativeConfig={status:check.status,...(check.code!==undefined?{code:check.code}:{})};
  if(check.status!=='ok')report.issues.push('native-config-check-failed');
  const capability=run(v.binary,['--capabilities']);report.checks.capabilities=capability.status==='ok'?JSON.parse(capability.stdout):capability;
  if(capability.status!=='ok')report.issues.push('native-capabilities-unavailable');
  const cert=new X509Certificate(file(c.role==='client'?c.ca:c.cert,1024*1024).bytes);
  report.certificate={kind:c.role==='client'?'local-CA-not-remote-leaf':'exit-leaf',validFrom:cert.validFrom,validTo:cert.validTo,
    fingerprint256:cert.fingerprint256,validAtLocalClock:Date.now()>=Date.parse(cert.validFrom)&&Date.now()<=Date.parse(cert.validTo)};
  if(!report.certificate.validAtLocalClock)report.issues.push('local-clock-outside-certificate-validity');
  if(c.tls_profile_path){const p=file(c.tls_profile_path,16384);report.profile={sha256:createHash('sha256').update(p.bytes).digest('hex'),nativeValidation:check.status};}
  if(v['gateway-config']){const g=validateGatewayConfig(JSON.parse(file(v['gateway-config'],32768).bytes));report.gateway=g;report.issues.push('gateway-topology-and-dns-owner-review-required');}
  report.namespace=fs.readlinkSync('/proc/self/ns/net');
  for(const [name,bin,args] of [
    ['links','ip',['-j','link','show']],['addresses','ip',['-j','address','show']],
    ['routes4','ip',['-j','-4','route','show','table','all']],['routes6','ip',['-j','-6','route','show','table','all']],
    ['rules4','ip',['-j','-4','rule','show']],['rules6','ip',['-j','-6','rule','show']],
    ['forwarding','sysctl',['-n','net.ipv4.ip_forward']],['firewall4','iptables-nft',['--version']],['firewall6','ip6tables-nft',['--version']],
  ]){report.checks[name]=run(bin,args);if(report.checks[name].status!=='ok')report.issues.push(name+'-unavailable');}
  try{report.resolver=fs.readFileSync('/etc/resolv.conf','utf8').slice(0,8192).split('\n').filter(l=>/^\s*(?:nameserver|search|options)\b/.test(l));}
  catch(e){report.resolver={status:'unavailable',code:e.code};}
  if(v.unit){assert.match(v.unit,/^[a-zA-Z0-9_-]+\.service$/);report.checks.unit=run('systemctl',['show',v.unit,'-p','Id','-p','ActiveState','-p','Result','-p','ExecMainStatus']);}
  report.status=report.issues.length?'review-required':'offline-checks-passed';
}catch(e){report.status='failed';report.issues.push(e.code??'invalid-input-or-local-inventory');}
console.log('=== CLEAN-VPN NATIVE RUNTIME PREFLIGHT BEGIN ===');console.log(JSON.stringify(report,null,2));console.log('=== CLEAN-VPN NATIVE RUNTIME PREFLIGHT END ===');
if(report.status!=='offline-checks-passed')process.exitCode=1;
