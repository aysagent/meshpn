import test from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs, measurementPlan, counterDelta } from '../scripts/perf-lib.mjs';
import { cleanStatus, executeSchedule } from '../scripts/perf-runner.mjs';
import { validateWifiTxExperiment, wifiTxCounterFields, wifiMarkdown } from '../scripts/perf-wifi.mjs';

test('AP upload preset: bounded long tests, only AP/up/TCP, warmup and recovery',async()=>{
  const o=parseArgs(['--ap-tcp-up','server']);
  assert.equal(o.seconds,30);assert.equal(o.runs,3);assert.equal(o.paths,'ap');
  for(const args of [['--quick'],['--paths','usb'],['--seconds','3'],['--soak-minutes','1'],['--usb-burst-sweep']])
    assert.throws(()=>parseArgs(['server','--ap-tcp-up',...args]));
  assert.equal(parseArgs(['--seconds','60','--ap-tcp-up','server']).seconds,60);
  const paths=[{kind:'ap'}],plan=measurementPlan(paths,o);
  assert.equal(plan.length,4);assert.equal(plan.filter(r=>!r.warmup).length,3);
  assert.ok(plan.every(r=>r.protocol==='tcp'&&r.direction==='up'&&r.seconds===30));
  assert.throws(()=>measurementPlan([{kind:'usb'}],o));
  const batches=[],idles=[];
  await executeSchedule(o,paths,{batch:async t=>batches.push(t),idle:async (name,s)=>idles.push([name,s])});
  assert.deepEqual(batches,plan);assert.equal(idles.length,5);assert.ok(idles.every(([,s])=>s===10));
});

test('Wi-Fi diagnostics preserve separate counter deltas, unknown/reset and sanitized peers',()=>{
  const state=n=>({uptime_sec:n,wifi:{tx:{available:true,buffer_type:'static',static_buffer_count:24,cache_buffer_count:128,amsdu_enabled:true,
    ...Object.fromEntries(['sta','ap'].map(k=>[k,Object.fromEntries(wifiTxCounterFields.map(f=>[f,n]))]))},
    radio:{sta_bandwidth_mhz:40,clients_available:true,clients:[{index:0,rssi:-50,phy_11n:true,mac:'secret'}],password:'secret'}}});
  const before=cleanStatus(state(10)),after=cleanStatus(state(20));
  const d=counterDelta(before,after);
  assert.equal(d['wifi.tx.sta.calls'],10);assert.equal(d['wifi.tx.ap.no_mem'],10);
  assert.equal(counterDelta(after,before)['wifi.tx.ap.calls'],null);
  assert.equal(counterDelta(cleanStatus({}),after)['wifi.tx.sta.calls'],null);
  assert.ok(!JSON.stringify(after).includes('secret'));
  assert.equal(after.wifi.tx.buffer_type,'static');assert.equal(after.wifi.tx.static_buffer_count,24);
  assert.equal(after.wifi.tx.cache_buffer_count,128);
  assert.equal(after.wifi.tx.amsdu_enabled,true);
  const r={id:'0001',batch_counters:d,batch_wifi:{before:before.wifi,after:after.wifi}};
  const text=wifiMarkdown([r,r]).join('\n');
  assert.equal(text.split('| 0001 | sta |').length-1,1);
  assert.ok(text.includes('40 / n/a'));assert.ok(text.includes('0: -50, true'));
  assert.ok(text.includes('static=24'));assert.ok(text.includes('cache=128'));assert.ok(text.includes('A-MSDU=true'));
  assert.ok(text.includes('NOT per-packet negotiated width'));
  assert.ok(wifiMarkdown([{...r,batch_counters:{}}]).join('\n').includes('| n/a |'));
  assert.deepEqual(wifiMarkdown([{id:'old'}]),[]);
  assert.equal(validateWifiTxExperiment(after.wifi.tx),null);
  assert.match(validateWifiTxExperiment({...after.wifi.tx,cache_buffer_count:48}),/cache=48/);
  assert.match(validateWifiTxExperiment({...after.wifi.tx,amsdu_enabled:false}),/A-MSDU=false/);
  assert.match(validateWifiTxExperiment({}),/telemetry/);
});
