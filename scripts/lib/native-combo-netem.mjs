// Fault injection and evidence policy for the isolated container lab only.
import assert from 'node:assert/strict';

export const netemPhases = Object.freeze([
  {name:'delay',seconds:30,args:['delay','60ms','10ms','distribution','normal'],minimumSuccess:.9},
  {name:'loss',seconds:45,args:['delay','20ms','loss','1%'],minimumSuccess:.7},
  {name:'reorder',seconds:30,args:['delay','40ms','reorder','25%','50%'],minimumSuccess:.9},
  {name:'blackout',seconds:8,args:['loss','100%'],minimumSuccess:0},
]);

export function netemCommands(role, phase) {
  assert.ok(['client','exit'].includes(role));
  assert.ok(netemPhases.includes(phase), 'fixed_lab_fault_only');
  return [
    ['qdisc','add','dev','eth0','root','handle','1:','prio','bands','3','priomap',...Array(16).fill('2')],
    ['qdisc','add','dev','eth0','parent','1:2','handle','20:','netem','limit','1000',...phase.args],
    ['filter','add','dev','eth0','parent','1:','protocol','ip','prio','1','u32',
      'match','ip','protocol','6','0xff','match','ip','dst',role==='client'?'10.77.0.2/32':'10.77.0.3/32',
      'match','ip',role==='client'?'dport':'sport','3443','0xffff','flowid','1:2'],
  ];
}

export const tcpCountersProbe = String.raw`
const fs=require('node:fs');const out={};
for(const file of ['netstat','snmp']){
 const lines=fs.readFileSync('/proc/net/'+file,'utf8').trim().split('\n');
 for(let i=0;i+1<lines.length;i+=2){const keys=lines[i].trim().split(/\s+/),values=lines[i+1].trim().split(/\s+/);
  for(let j=1;j<keys.length;j++)out[keys[0].slice(0,-1)+keys[j]]=Number(values[j]);}
}
const result={outOfOrder:out.TcpExtTCPOFOQueue,retransmits:out.TcpRetransSegs};
if(!Object.values(result).every(Number.isSafeInteger))throw Error('tcp_counters_unavailable');
console.log(JSON.stringify(result));`;

// Every received body is checked, even under loss. No TLS verification bypass.
export const bulkRelayProbe = String.raw`
const https=await import('node:https'),fs=await import('node:fs'),{createHash}=await import('node:crypto');
const expected=Buffer.alloc(256*1024,0x5a),digest=createHash('sha256').update(expected).digest('hex');
await new Promise((resolve,reject)=>{
 let bytes=0,finished=false;const hash=createHash('sha256');
 const done=error=>{if(finished)return;finished=true;clearTimeout(timer);error?reject(error):resolve();};
 const req=https.get({host:'11.22.33.44',port:443,path:'/bulk',servername:'runtime.test',
   ca:fs.readFileSync('/config/cert.pem'),agent:false},res=>{
  if(res.statusCode!==200){req.destroy();return done(Error('integrity_status'));}
  res.on('data',b=>{bytes+=b.length;if(bytes>expected.length){req.destroy();done(Error('integrity_size'));}else hash.update(b);});
  res.on('error',done);res.on('aborted',()=>done(Error('response_aborted')));
  res.on('end',()=>done(bytes===expected.length&&hash.digest('hex')===digest?null:Error('integrity_body')));
 });
 const timer=setTimeout(()=>{req.destroy();done(Error('relay_deadline'));},8000);
 req.on('error',done);
});`;

export function faultWorkload(packetProbe, seconds) {
  assert.ok(Number.isInteger(seconds)&&seconds>=8&&seconds<=60);
  return `const output=console.log;console.log=()=>{};
const packet=async()=>{${packetProbe}},relay=async()=>{${bulkRelayProbe}};
const stats={packet:{attempts:0,success:0,errors:{}},relay:{attempts:0,success:0,errors:{}},integrityErrors:0};
const one=async(kind,fn)=>{const s=stats[kind];s.attempts++;try{await fn();s.success++;}catch(e){
 const key=e.code??e.message;s.errors[key]=(s.errors[key]??0)+1;if(String(key).startsWith('integrity_'))stats.integrityErrors++;}};
const start=performance.now();do{await Promise.all([one('packet',packet),one('relay',relay),one('relay',relay)]);
 await new Promise(r=>setTimeout(r,200));}while(performance.now()-start<${seconds*1000});
output('NETEM_LOAD='+JSON.stringify({...stats,elapsedMs:performance.now()-start}));`;
}

export function assertNetemEvidence(phase, result) {
  assert.ok(netemPhases.includes(phase));
  const load=result.load;
  assert.ok(Number.isFinite(load.elapsedMs)&&load.elapsedMs>=phase.seconds*1000&&load.elapsedMs<(phase.seconds+30)*1000,'fault_duration');
  assert.equal(load.integrityErrors,0,'corrupt_application_data');
  for(const kind of ['packet','relay']){
    const s=load[kind];
    assert.ok(Number.isSafeInteger(s.attempts)&&s.attempts>0&&Number.isSafeInteger(s.success)&&s.success>=0&&s.success<=s.attempts,'branch_attempts');
    const errors=Object.values(s.errors);assert.ok(errors.every(n=>Number.isSafeInteger(n)&&n>0));
    assert.equal(s.success+errors.reduce((a,b)=>a+b,0),s.attempts,'missing_attempt_outcome');
    if(phase.name==='blackout')assert.equal(s.success,0,'blackout_bypass');
    else assert.ok(s.success/s.attempts>=phase.minimumSuccess,'fault_success_floor_'+kind);
  }
  let drops=0,outOfOrder=0;
  for(const role of ['client','exit']){
    const q=result.qdisc[role].find(q=>q.kind==='netem'&&q.handle==='20:');assert.ok(q,'netem_missing');
    assert.equal(q.options?.limit,1000,'netem_queue_limit');
    const close=(actual,expected)=>assert.ok(Number.isFinite(actual)&&Math.abs(actual-expected)<1e-6,'netem_options_changed');
    if(phase.name==='delay'){close(q.options.delay?.delay,.06);close(q.options.delay?.jitter,.01);}
    if(phase.name==='loss'){close(q.options.delay?.delay,.02);close(q.options['loss-random']?.loss,.01);}
    if(phase.name==='reorder'){close(q.options.delay?.delay,.04);close(q.options.reorder?.reorder,.25);}
    if(phase.name==='blackout')close(q.options['loss-random']?.loss,1);
    for(const k of ['packets','drops'])assert.ok(Number.isSafeInteger(q[k])&&q[k]>=0,'qdisc_counters');
    assert.ok(q.packets+q.drops>0,'fault_did_not_receive_traffic');drops+=q.drops;
    const before=result.before[role],after=result.after[role];
    for(const k of ['outOfOrder','retransmits'])assert.ok(Number.isSafeInteger(before[k])&&Number.isSafeInteger(after[k])&&after[k]>=before[k],'tcp_counter_reset');
    outOfOrder+=after.outOfOrder-before.outOfOrder;
  }
  if(['loss','blackout'].includes(phase.name))assert.ok(drops>0,'loss_not_observed');
  if(phase.name==='reorder')assert.ok(outOfOrder>0,'out_of_order_not_observed');
  return {drops,outOfOrder};
}
