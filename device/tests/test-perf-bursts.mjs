import test from 'node:test';
import assert from 'node:assert/strict';
import { cleanBursts, readBursts, burstDelta, burstMarkdown } from '../scripts/perf-bursts.mjs';
import { parseArgs, measurementPlan } from '../scripts/perf-lib.mjs';
const row=(seq,extra={})=>({seq,window_us:seq*1000,first_full_us:seq*1000+10,submitted:10,full:2,
  epoch:1,in_use:8,worker_started_us:0,last_completed_us:0,ncm_captured_us:seq*1000+20,
  ncm_sampled_us:seq*1000,ncm_free:0,ncm_ready:5,worker_active:true,worker_waiting:true,
  ncm_available:true,ncm_active:true,ncm_glue:false,...extra});
const snap=(n,extra={})=>({version:1,available:true,window_us:1000,capacity:32,session_id:7,
  sampled_us:n*1000+500,latest_seq:n,submitted:n*10,full:n*2,windows:n,arrival_hist:[0,0,n,0],
  records:Array.from({length:Math.min(n,32)},(_,i)=>row(Math.max(0,n-32)+i+1)),...extra});
test('strict bounded schema strips unknown sensitive fields',()=>{
  const s=snap(2);s.token='secret';s.records[0].payload='secret';
  assert(!JSON.stringify(cleanBursts(s)).includes('secret'));
  for(const bad of [null,{},snap(2,{version:2}),snap(2,{records:[]}),snap(2,{submitted:NaN}),snap(2,{arrival_hist:[0,0,2,1]})])
    assert.throws(()=>cleanBursts(bad));
  assert.throws(()=>cleanBursts(snap(1,{records:[row(1,{in_use:9})]})));
  assert.throws(()=>cleanBursts(snap(1,{records:[row(1,{worker_active:1})]})));
});
test('exact totals, boundary record updates and old-state flags',()=>{
  const before=cleanBursts(snap(1));
  const after=cleanBursts(snap(2,{full:5,submitted:21,records:[row(1,{full:3,submitted:11}),row(2)]}));
  const d=burstDelta(before,after);
  assert.equal(d.full,3);assert.equal(d.submitted,11);assert.deepEqual(d.arrival_hist,[0,0,1,0]);
  assert.equal(d.records.length,2);assert.equal(d.records[0].interval_full,1);
  assert(d.records[0].start_partial && d.records[0].snapshot_before_interval);
  assert(d.records[1].end_partial);assert.equal(d.unrepresented_full,0);assert.equal(d.missing_windows,0);
});
test('ring overflow retains latest detail, totals include missing old windows',()=>{
  const d=burstDelta(cleanBursts(snap(1)),cleanBursts(snap(40)));
  assert(d.available);assert.equal(d.full,78);assert.equal(d.records.length,32);
  assert.equal(d.missing_windows,7);assert.equal(d.unrepresented_full,14);
  assert.match(d.warnings.join(' '),/overwritten/);
  const md=burstMarkdown([{id:'0001',batch_bursts:d},{id:'0001',batch_bursts:d}]).join('\n');
  assert.equal((md.match(/\| 0001 \/ /g)||[]).length,3);assert.match(md,/not physical packet arrival/);
});
test('empty intervals and resets are not confused',()=>{
  const s=cleanBursts(snap(0));const d=burstDelta(s,s);
  assert(d.available);assert.equal(d.full,0);assert.equal(d.records.length,0);
  for(const after of [snap(1,{session_id:8}),snap(0)])
    assert.equal(burstDelta(cleanBursts(snap(1)),cleanBursts(after)).available,false);
});
test('unsupported/error API is nonfatal and never persists arbitrary error text',async()=>{
  for(const board of [{},{bursts:async()=>null},{bursts:async()=>{throw Error('Bearer secret');}},{bursts:async()=>({secret:1})}]) {
    const s=await readBursts(board);assert.equal(s.available,false);
    const d=burstDelta(s,s);assert.match(d.warnings[0],/not a clean test/);
    assert(!JSON.stringify(d).includes('secret'));
  }
  assert.deepEqual(await readBursts({bursts:async()=>snap(1)}),cleanBursts(snap(1)));
});
test('short sweep selects only 6/7/8M, preserves warmups and avoids conflicting presets',()=>{
  const o=parseArgs(['server','--usb-burst-sweep']);
  const p=measurementPlan([{kind:'usb'}],o);
  assert(o.usbDownSweep && o.usbBurstSweep);assert.equal(p.length,12);
  assert.deepEqual([...new Set(p.map(r=>r.rate))],[6,7,8]);
  assert.equal(p.filter(r=>r.warmup).length,3);assert.equal(p.filter(r=>!r.warmup).length,9);
  assert.throws(()=>parseArgs(['server','--usb-burst-sweep','--quick']));
  assert.throws(()=>parseArgs(['server','--usb-burst-sweep','--paths','ap']));
});
