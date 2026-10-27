import assert from 'node:assert/strict';

// Runs inside the engine's PID/network namespace. No argv/environment/keys.
export const nativeProcessProbe = String.raw`
const fs=require('node:fs');
const status=fs.readFileSync('/proc/1/status','utf8');
const executable=fs.readlinkSync('/proc/1/exe');
if(!executable.endsWith('/clean-vpn-engine'))throw Error('native_pid1_required');
const fds=fs.readdirSync('/proc/1/fd');
const targets=fds.flatMap(n=>{try{return [fs.readlinkSync('/proc/1/fd/'+n)];}catch(e){if(e.code!=='ENOENT')throw e;return [];}});
let nativeProcesses=0,zombies=0;
const pids=fs.readdirSync('/proc').filter(n=>/^\d+$/.test(n));
for(const pid of pids){try{
 const s=fs.readFileSync('/proc/'+pid+'/status','utf8');
 if(/^State:\s+Z/m.test(s))zombies++;
 try{if(fs.readlinkSync('/proc/'+pid+'/exe')===executable)nativeProcesses++;}
 catch(e){if(e.code!=='ENOENT')throw e;}
}catch(e){if(e.code!=='ENOENT')throw e;}}
const rows=name=>fs.readFileSync('/proc/1/net/'+name,'utf8').trim().split('\n').slice(1).map(l=>l.trim().split(/\s+/));
const tcp=[...rows('tcp'),...rows('tcp6')];
console.log(JSON.stringify({rssKiB:Number(status.match(/^VmRSS:\s+(\d+)/m)[1]),fds:fds.length,
 sockets:targets.filter(t=>t.startsWith('socket:[')).length,threads:Number(status.match(/^Threads:\s+(\d+)/m)[1]),
 nativeProcesses,namespaceProcesses:pids.length,zombies,
 tcpEstablished:tcp.filter(r=>r[3]==='01').length,tcpTimeWait:tcp.filter(r=>r[3]==='06').length,
 udpSockets:rows('udp').length+rows('udp6').length}));
`;

export function latencySummary(values) {
  assert.ok(values.length && values.every(v => Number.isFinite(v) && v >= 0));
  const sorted = [...values].sort((a,b) => a-b);
  const percentile = p => sorted[Math.max(0, Math.ceil(p * sorted.length) - 1)];
  return { samples: sorted.length, minMs: sorted[0], p50Ms: percentile(.5), p95Ms: percentile(.95), maxMs: sorted.at(-1),
    scope: 'probe-plus-container-exec-wall-time-not-network-RTT' };
}
