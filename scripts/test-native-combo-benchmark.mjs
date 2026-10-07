import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { assertBenchmarkSample, assertComboBenchmark, runComboBenchmark } from './lib/native-combo-benchmark.mjs';
import { assertComboNetworkEvidence } from './lib/native-combo-network-evidence.mjs';

const sample = (branch,phase) => ({ status:'passed',branch,phase,payloadVerified:true,streams:1,
  seconds:0.5,clockTicksPerSecond:100,payloadBytes:phase==='latency'?0:8*1048576,
  rounds:phase==='latency'?100:0,warmupRounds:phase==='latency'?5:0,
  goodputMbps:phase==='latency'?0:8*1048576*8/0.5/1e6,
  latencyMedianMs:phase==='latency'?1:0,latencyP95Ms:phase==='latency'?2:0 });
test('device build includes every registered CTest executable',()=>{
  const cmake=fs.readFileSync(new URL('../native/clean_vpn/CMakeLists.txt',import.meta.url),'utf8');
  const script=fs.readFileSync(new URL('./build-clean-vpn-native.sh',import.meta.url),'utf8');
  const targets=script.match(/--target (.+?) --parallel/)?.[1].split(/\s+/);assert.ok(targets);
  const tests=[...cmake.matchAll(/add_test\(NAME \S+ COMMAND ([\w-]+)/g)];assert.ok(tests.length>=7);
  for(const [,target] of tests) assert.ok(targets.includes(target),`device_build_missing_${target}`);
});
function harness({ change, snapshotChange, hang=false }={}) {
  let time=0,packets=0,job=null;
  return [{
    snapshot:()=>snapshotChange?.() ?? {client:{start:'10',ticks:time/100,rss:6000},exit:{start:'20',ticks:time/100,rss:6100}},
    tunPackets:()=>packets,
    start:(branch,phase)=>{job={ended:false,code:0,output:JSON.stringify({...sample(branch,phase),...change}),error:''};if(branch==='boring')packets+=100;return job;},
  }, {now:()=>time,pause:async()=>{time+=1000;if(!hang)job.ended=true;}}];
}
test('directional benchmark enforces bytes, units, payload verification and RTT sample size',()=>{
  for(const phase of ['upload','download','latency']) assertBenchmarkSample(sample('boring',phase));
  for(const patch of [{payloadVerified:false},{payloadBytes:1},{goodputMbps:1},{seconds:0},{seconds:NaN},{streams:2},
    {clockTicksPerSecond:0},{latencyMedianMs:1},{branch:'legacy'},{phase:'echo'}])
    assert.throws(()=>assertBenchmarkSample({...sample('boring','upload'),...patch}));
  for(const patch of [{rounds:99},{warmupRounds:0},{latencyP95Ms:Infinity},{latencyP95Ms:0.5}])
    assert.throws(()=>assertBenchmarkSample({...sample('transparent','latency'),...patch}));
});
test('benchmark keeps separate timing windows, samples both roles and checks TUN branch selection',async()=>{
  const r=await runComboBenchmark(...harness());assertComboBenchmark(r);assert.equal(r.samples.length,18);
  assert.equal(r.samples[0].goodputMbps,134.217728); // Decimal megabits, not MiB/s or echo x2.
  assert.equal(r.samples[0].roles.client.cpuSeconds,0.1);assert.equal(r.samples[0].roles.client.cpuPercentOneCore,10);
  for(const change of [r=>r.samples.pop(),r=>r.samples[0].roles.client.cpuSeconds=10,
    r=>r.samples[0].tunPacketDelta=0,r=>r.samples[3].tunPacketDelta=1,r=>r.samples[0].repetition=3,
    r=>r.samples[0].wallSeconds=0.1,r=>r.scope='Internet speed',r=>delete r.samples[0].roles.exit]) {
    const bad=structuredClone(r);change(bad);assert.throws(()=>assertComboBenchmark(bad));
  }
});
test('benchmark rejects incomplete, corrupt and stalled runs',async()=>{
  for(const change of [{status:'failed'},{payloadVerified:false},{branch:'legacy'}])
    await assert.rejects(runComboBenchmark(...harness({change})));
  await assert.rejects(runComboBenchmark(...harness({hang:true})),/deadline/);
  let n=0;
  await assert.rejects(runComboBenchmark(...harness({snapshotChange:()=>({client:{start:String(n++),ticks:0,rss:6000},exit:{start:'20',ticks:0,rss:6100}})})),/benchmark_engine_replaced/);
});
test('network acceptance cannot substitute a short smoke for benchmark or load',async()=>{
  const recorded=JSON.parse(fs.readFileSync(new URL('./fixtures/clean-vpn-native-combo-benchmark-report.json',import.meta.url)));
  for(const run of [recorded,recorded.previousRun]) {
    assert.equal(run.status,'passed');assert.equal(run.accelerator,'TCG');assert.equal(run.nic,'none');
    assert.equal(run.hostSharedFilesystem,false);assert.equal(run.packetOwner,'C++');
    assertComboNetworkEvidence(run.evidence,{benchmark:true});
  }
  const e=JSON.parse(fs.readFileSync(new URL('./fixtures/clean-vpn-native-combo-network-report.json',import.meta.url))).evidence;
  assert.throws(()=>assertComboNetworkEvidence(e,{benchmark:true}));
  e.benchmark=await runComboBenchmark(...harness());e.checks.splice(7,0,'DIRECTIONAL_BENCHMARK');
  e.scope='runtime-static-routes-selected-IPv4-origin-with-emulated-benchmark';
  assertComboNetworkEvidence(e,{benchmark:true});
  assert.throws(()=>assertComboNetworkEvidence(e));assert.throws(()=>assertComboNetworkEvidence(e,{benchmark:true,load:true}));
});
test('C++ benchmark self-test and refusal outside isolated lab network',()=>{
  const bin=path.resolve(process.env.CVPN_BUILD ?? 'native/clean_vpn/build','throughput-test');
  assert.equal(spawnSync(bin,['--self-test'],{timeout:30000}).status,0);
  const parent=fs.readlinkSync('/proc/self/ns/net');
  for(const args of [[],['--server',parent],['upload','boring','unused',parent,'--lab-only'],
    ['latency','transparent','unused',parent,'--lab-only'],['upload','boring','unused','net:[1]','--lab-only']]) {
    const r=spawnSync(bin,args,{timeout:5000,encoding:'utf8'});assert.notEqual(r.status,0);assert.equal(r.signal,null);assert.equal(r.stdout,'');
  }
});
