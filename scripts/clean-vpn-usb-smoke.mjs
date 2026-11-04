#!/usr/bin/env node
// macOS process-only USB checks: no route, DNS, proxy or trust-store changes.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const exec=promisify(execFile),options={};
for(const a of process.argv.slice(2)){const m=/^--(interface|source|gateway|expected-exit)=(.+)$/.exec(a);assert(m&&!Object.hasOwn(options,m[1]),'usage: --interface=enN --source=USB_CLIENT_IP --gateway=BOARD_USB_IP --expected-exit=EXIT_IP');options[m[1]]=m[2];}
assert.equal(process.platform,'darwin');assert(/^en[0-9]+$/.test(options.interface));
for(const k of ['source','gateway','expected-exit'])assert(net.isIPv4(options[k]),k);
assert(['192.168.7.1','192.168.8.1'].includes(options.gateway));
assert(options.source.startsWith(options.gateway.slice(0,options.gateway.lastIndexOf('.')+1)));
assert(os.networkInterfaces()[options.interface]?.some(a=>a.family==='IPv4'&&a.address===options.source),'USB_source_not_on_interface');
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-usb-smoke-'));
const report={schema:1,kind:'clean-vpn-usb-smoke',timestamp:new Date().toISOString(),...options,systemNetworkChanged:false,tlsValidation:true,browserAcceptance:false,dns:[],requests:[]};
const cache=new Map();
async function dns(host,type='A',tcp=false){
 const {stdout}=await exec('/usr/bin/dig',['-b',options.source,'@'+options.gateway,host,type,'+time=3','+tries=1','+short',...(tcp?['+tcp']:[])],{timeout:5000,maxBuffer:65536});
 const addresses=stdout.trim().split(/\s+/).filter(v=>type==='A'?net.isIPv4(v):net.isIPv6(v));assert(addresses.length,'DNS_no_addresses');
 report.dns.push({host,type,transport:tcp?'tcp':'udp',addresses});return addresses;
}
async function request(url,{upload=false,exit=false,downloadBytes}={}){
 const u=new URL(url),port=u.port||(u.protocol==='https:'?'443':'80');
 if(!cache.has(u.hostname))cache.set(u.hostname,await dns(u.hostname));
 const addresses=cache.get(u.hostname),attempts=[];
 for(const address of addresses.slice(0,2)){
  const file=path.join(tmp,'body'),args=['--ipv4','--noproxy','*','--interface',options.interface,'--resolve',`${u.hostname}:${port}:${address}`,'--connect-timeout','5','--max-time','20','--max-filesize','8388608','--silent','--show-error','--output',file,'--write-out','%{json}'];
  if(upload)args.push('--request','POST','--data-binary','@'+path.join(tmp,'upload'));
  fs.rmSync(file,{force:true});
  let stats,error;
  try{const {stdout}=await exec('/usr/bin/curl',[...args,url],{timeout:23000,maxBuffer:65536});stats=JSON.parse(stdout);}catch(e){error=e.code??'request_failed';try{stats=JSON.parse(e.stdout);}catch{}}
  const body=fs.existsSync(file)?fs.readFileSync(file):Buffer.alloc(0);
  const passed=!error&&stats?.local_ip===options.source&&stats.http_code>=200&&stats.http_code<400&&(!exit||body.toString().trim()===options['expected-exit'])&&(!upload||stats.size_upload===262144)&&(downloadBytes===undefined||(stats.size_download===downloadBytes&&body.length===downloadBytes));
  attempts.push({address,passed,error,status:stats?.http_code,local:stats?.local_ip,remote:stats?.remote_ip,seconds:stats?.time_total,downloadBytes:stats?.size_download,uploadBytes:stats?.size_upload,...(exit?{observedExit:body.toString().trim().slice(0,64)}:{})});
  if(passed)break;
 }
 report.requests.push({url,passed:attempts.some(a=>a.passed),attempts});
}
try{
 fs.writeFileSync(path.join(tmp,'upload'),Buffer.alloc(262144,0x5a));
 for(const type of ['A','AAAA'])for(const tcp of [false,true])await dns('example.org',type,tcp);
 for(const url of ['http://example.org/','https://example.org/','https://internet.yandex.ru/','https://www.speedtest.net/'])await request(url);
 await request('http://api.ipify.org/',{exit:true});
 await request('https://api.ipify.org/',{exit:true});
 await request('https://speed.cloudflare.com/__down?bytes=1048576',{downloadBytes:1048576});
 await request('https://speed.cloudflare.com/__up',{upload:true});
 report.status=report.requests.every(r=>r.passed)?'passed':'failed';
}catch(e){report.status='failed';report.error=e.code??e.message;}
finally{fs.rmSync(tmp,{recursive:true,force:true});console.log(JSON.stringify(report,null,2));if(report.status!=='passed')process.exitCode=1;}
