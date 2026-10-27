import assert from 'node:assert/strict';
import { isIPv4 } from 'node:net';

// Timing happens INSIDE the application namespace. These are individual
// DNS / TLS+HTTP / echo transactions, not CLI startup or throughput samples.
export function applicationProbe(dnsAddress = '127.0.0.11') {
  assert.ok(isIPv4(dnsAddress));
  return `const dnsAddress=${JSON.stringify(dnsAddress)};` + String.raw`
const {dnsProbe}=await import('/opt/clean-vpn/clean-vpn-native-runtime-health.mjs');
const https=await import('node:https'),fs=await import('node:fs');
const net=await import('node:net'),dgram=await import('node:dgram');
const timings={};
const timed=async(name,fn)=>{const began=performance.now();await fn();timings[name]=performance.now()-began;};
await Promise.all([false,true].map(t=>timed(t?'dnsTcpMs':'dnsUdpMs',()=>dnsProbe(dnsAddress,53,t))));
await timed('httpsRequestMs',()=>new Promise((resolve,reject)=>{
 https.get({host:'198.18.0.80',port:8443,servername:'runtime.test',ca:fs.readFileSync('/config/cert.pem'),agent:false,timeout:4000},r=>{
 let b='';r.on('data',x=>b+=x);r.on('end',()=>b==='native-runtime-https-ok\n'?resolve():reject(Error('https_body')));
 }).on('error',reject).on('timeout',function(){this.destroy(Error('timeout'));});
}));
await timed('tcpEchoMs',()=>new Promise((resolve,reject)=>{
 const s=net.connect(8080,'198.18.0.80',()=>s.write('native-echo'));s.setTimeout(4000,()=>s.destroy(Error('timeout')));
 s.on('error',reject);s.on('data',b=>{s.destroy();b.toString()==='native-echo'?resolve():reject(Error('tcp_echo'));});
}));
await timed('udpEchoMs',()=>new Promise((resolve,reject)=>{
 const s=dgram.createSocket('udp4');const t=setTimeout(()=>{s.close();reject(Error('udp_timeout'));},4000);
 s.on('error',e=>{clearTimeout(t);s.close();reject(e);});
 s.on('message',b=>{clearTimeout(t);s.close();b.toString()==='native-echo'?resolve():reject(Error('udp_echo'));});
 s.send('native-echo',8081,'198.18.0.80');
}));
console.log('APPLICATION_TIMINGS='+JSON.stringify(timings));
console.log('APPLICATION_PROBES_OK');
`;
}

export function parseApplicationTimings(output) {
  const rows = output.split('\n').filter(l => l.startsWith('APPLICATION_TIMINGS='));
  assert.equal(rows.length, 1, 'one_complete_application_timing_record_required');
  assert.ok(output.split('\n').includes('APPLICATION_PROBES_OK'), 'successful_probe_required');
  const timings = JSON.parse(rows[0].slice('APPLICATION_TIMINGS='.length));
  assert.deepEqual(Object.keys(timings).sort(), ['dnsTcpMs','dnsUdpMs','httpsRequestMs','tcpEchoMs','udpEchoMs']);
  assert.ok(Object.values(timings).every(x => Number.isFinite(x) && x >= 0), 'invalid_transaction_duration');
  return timings;
}
