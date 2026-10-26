// Runs only inside the NIC-less disposable VM, never on the Mac or a live host.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {execFileSync} from 'node:child_process';
import {runH2Budget} from '../clean-vpn-native-h2-budget.mjs';
assert.match(fs.readFileSync('/proc/cmdline','utf8'),/\bmeshpn.h2-kernel=1\b/);
assert.deepEqual(fs.readdirSync('/sys/class/net'),['lo']);
const tc=(...args)=>execFileSync('/usr/sbin/tc',args,{encoding:'utf8'});
const reports=[];
const qdisc=()=>JSON.parse(tc('-s','-j','qdisc','show','dev','lo'));
try {
  for(const step of [
    {name:'kernel-matrix',delayMs:0,counts:[1,4,8],cycles:3},
    {name:'rtt-40ms',delayMs:20,counts:[4],cycles:3},
    {name:'soak',delayMs:0,counts:[4],cycles:30},
  ]){
    if(step.delayMs)tc('qdisc','add','dev','lo','root','netem','limit','10000','delay',step.delayMs+'ms');
    const before=qdisc();
    if(step.delayMs)assert.ok(before.some(q=>q.kind==='netem'));
    const ping=execFileSync('/bin/busybox',['ping','-n','-c','5','-W','2','127.0.0.1'],{encoding:'utf8'});
    const match=/round-trip min\/avg\/max = ([\d.]+)\/([\d.]+)\/([\d.]+)/.exec(ping);
    assert.ok(match,'measured loopback RTT required');
    const rtt={min:Number(match[1]),avg:Number(match[2]),max:Number(match[3])};
    if(step.delayMs)assert.ok(rtt.min>=step.delayMs*1.8&&rtt.avg<250,'netem RTT not observed');
    else assert.ok(rtt.avg<50,'unexpected baseline RTT');
    console.error('H2_KERNEL_STEP='+step.name);
    const result=await runH2Budget({counts:step.counts,cycles:step.cycles});
    assert.equal(result.kernelSocketMemoryComplete,true,'full Linux SO_MEMINFO required');
    const after=qdisc();
    if(step.delayMs)assert.ok(after.some(q=>q.kind==='netem'&&q.packets>0),'netem traffic evidence required');
    reports.push({...step,rttMs:rtt,qdiscBefore:before,qdiscAfter:after,result});
    if(step.delayMs)tc('qdisc','del','dev','lo','root');
  }
  console.log('H2_KERNEL_REPORT='+JSON.stringify({schema:1,kind:'clean-vpn-native-h2-kernel-report',status:'passed',
    nic:'none',hostSharedFilesystem:false,hostNetworkSettingsChanged:false,physicalHostsTouched:false,
    productionWindowIncreaseApproved:false,reports,
    limitations:['TCG-not-hardware-performance','socketpair-not-TUN','loopback-with-delay-not-WAN',
      'qdisc-and-TCP-accounting-not-total-kernel-memory','bounded-soak-not-long-term-proof','no-loss-or-bandwidth-model']}));
}finally{
  // Only lo inside this private VM; the VM is also powered off on failure.
  if(qdisc().some(q=>q.kind==='netem'))tc('qdisc','del','dev','lo','root');
}
