// Disposable VM only: observe process metadata, never application/packet bytes.
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';
assert.match(fs.readFileSync('/proc/cmdline','utf8'),/meshpn.native-lab=1/);
const [label,...roots]=process.argv.slice(2);assert.ok(roots.length===2&&roots.every(p=>/^\d+$/.test(p)));
const snapshots=new Map();let rssPeak=0,fdPeak=0,processPeak=0;
function sample(){
  const seen=new Set();let rss=0,fds=0;
  function visit(pid){
    if(seen.has(pid))return;seen.add(pid);
    try{
      const stat=fs.readFileSync(`/proc/${pid}/stat`,'utf8').split(') ')[1].split(' ');
      const ticks=Number(stat[11])+Number(stat[12]);
      const record=snapshots.get(pid)??{first:ticks,last:ticks};record.last=ticks;snapshots.set(pid,record);
      const status=fs.readFileSync(`/proc/${pid}/status`,'utf8');rss+=Number(status.match(/^VmRSS:\s+(\d+)/m)?.[1]??0);
      fds+=fs.readdirSync(`/proc/${pid}/fd`).length;
      for(const child of fs.readFileSync(`/proc/${pid}/task/${pid}/children`,'utf8').trim().split(/\s+/).filter(Boolean))visit(child);
    }catch{}
  }
  roots.forEach(visit);rssPeak=Math.max(rssPeak,rss);fdPeak=Math.max(fdPeak,fds);processPeak=Math.max(processPeak,seen.size);
}
sample();const timer=setInterval(sample,100);const start=performance.now();
const child=spawn('/usr/bin/ip',['netns','exec','peer','/native/socket-test','bench'],{stdio:['ignore','pipe','inherit']});
let output='';child.stdout.on('data',b=>{output+=b;assert.ok(output.length<4096);});
const deadline=setTimeout(()=>child.kill('SIGKILL'),120000);
const code=await new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',resolve);});
clearInterval(timer);clearTimeout(deadline);sample();assert.equal(code,0,output);
console.log('NATIVE_BENCH '+JSON.stringify({label,bytesEachDirection:16777216,wallSeconds:(performance.now()-start)/1000,
  applicationSeconds:Number(output.match(/seconds=([\d.]+)/)?.[1]),cpuTicks:[...snapshots.values()].reduce((s,r)=>s+r.last-r.first,0),
  latencyMedianMs:Number(output.match(/median_ms=([\d.]+)/)?.[1]),latencyP95Ms:Number(output.match(/p95_ms=([\d.]+)/)?.[1]),
  rssPeakKiB:rssPeak,fdPeak,processPeak,sampleMs:100,clockTicksPerSecond:100}));
