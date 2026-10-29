import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {netemPhases,netemCommands,assertNetemEvidence,faultWorkload,bulkRelayProbe} from './lib/native-combo-netem.mjs';
import {applicationProbe} from './lib/native-runtime-application-probe.mjs';

const evidence=phase=>({
  load:{elapsedMs:phase.seconds*1000,integrityErrors:0,
    ...Object.fromEntries(['packet','relay'].map(k=>[k,{attempts:10,success:phase.name==='blackout'?0:10,
      errors:phase.name==='blackout'?{timeout:10}:{}}]))},
  qdisc:Object.fromEntries(['client','exit'].map(r=>[r,[{kind:'netem',handle:'20:',packets:100,drops:2,options:{limit:1000,
    delay:{delay:{delay:.06,loss:.02,reorder:.04}[phase.name]??0,jitter:.01},
    'loss-random':{loss:phase.name==='blackout'?1:.01},reorder:{reorder:.25}}}]])),
  before:{client:{outOfOrder:0,retransmits:0},exit:{outOfOrder:0,retransmits:0}},
  after:{client:{outOfOrder:2,retransmits:1},exit:{outOfOrder:1,retransmits:1}},
});

test('netem targets only fixed lab peer TCP/3443 on the owning container uplink',()=>{
  for(const phase of netemPhases)for(const role of ['client','exit']){
    const commands=netemCommands(role,phase);
    assert.ok(commands.every(c=>c.includes('eth0')));
    assert.ok(commands.every(c=>!c.includes('replace')));
    const filter=commands[2].join(' ');
    assert.match(filter,/protocol 6 0xff/);
    assert.ok(filter.includes(role==='client'?'dst 10.77.0.2/32':'dst 10.77.0.3/32'));
    assert.ok(filter.includes(role==='client'?'dport 3443':'sport 3443'));
  }
  assert.throws(()=>netemCommands('host',netemPhases[0]));
  assert.throws(()=>netemCommands('client',{args:['arbitrary']}));
});
test('fault evidence requires completed work in both branches and actual impairment counters',()=>{
  for(const phase of netemPhases){
    assertNetemEvidence(phase,evidence(phase));
    for(const mutate of [r=>r.load.packet.attempts=0,r=>r.load.elapsedMs=1,
      r=>r.load.integrityErrors=1,r=>r.qdisc.client=[],r=>r.qdisc.client[0].packets=-1,
      r=>r.after.client.outOfOrder=-1,r=>r.load.packet.success=11,
      r=>r.load.packet.errors.extra=1,r=>r.qdisc.exit[0].options={}]){
      const r=evidence(phase);mutate(r);assert.throws(()=>assertNetemEvidence(phase,r));
    }
  }
  for(const phase of netemPhases.filter(p=>['loss','blackout'].includes(p.name))){
    const r=evidence(phase);r.qdisc.client[0].drops=r.qdisc.exit[0].drops=0;
    assert.throws(()=>assertNetemEvidence(phase,r),/loss_not_observed/);
  }
  const phase=netemPhases.find(p=>p.name==='reorder'),r=evidence(phase);
  r.after.client.outOfOrder=r.after.exit.outOfOrder=0;
  assert.throws(()=>assertNetemEvidence(phase,r),/out_of_order_not_observed/);
});
test('partial loss has an explicit success floor; blackout must never succeed',()=>{
  const loss=netemPhases.find(p=>p.name==='loss'),r=evidence(loss);
  r.load.packet.success=7;r.load.packet.errors={timeout:3};assertNetemEvidence(loss,r);
  r.load.packet.success=6;r.load.packet.errors={timeout:4};assert.throws(()=>assertNetemEvidence(loss,r),/success_floor/);
  const blackout=netemPhases.find(p=>p.name==='blackout'),b=evidence(blackout);
  b.load.relay.success=1;b.load.relay.errors={timeout:9};assert.throws(()=>assertNetemEvidence(blackout,b),/blackout_bypass/);
});
test('generated bulk/probe workloads parse and reject unbounded durations',()=>{
  new vm.Script('(async()=>{'+bulkRelayProbe+'})()');
  for(const phase of netemPhases)new vm.Script('(async()=>{'+faultWorkload(applicationProbe('192.168.88.2'),phase.seconds)+'})()');
  for(const seconds of [0,7,61,Infinity,'30'])assert.throws(()=>faultWorkload('',seconds));
});
