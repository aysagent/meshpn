// Strict allowlist: never persist an arbitrary API response (credentials/payloads).
const totals=['session_id','sampled_us','latest_seq','submitted','full','windows'];
const numbers=['seq','window_us','first_full_us','submitted','full','epoch','in_use',
  'worker_started_us','last_completed_us','ncm_captured_us','ncm_sampled_us','ncm_free','ncm_ready'];
const booleans=['worker_active','worker_waiting','ncm_available','ncm_active','ncm_glue'];
const uint=n=>Number.isSafeInteger(n)&&n>=0;
export function cleanBursts(s) {
  if(!s||s.version!==1||typeof s.available!=='boolean'||s.window_us!==1000||s.capacity!==32||
    !totals.every(k=>uint(s[k]))||!Array.isArray(s.arrival_hist)||s.arrival_hist.length!==4||
    !s.arrival_hist.every(uint)||!Array.isArray(s.records)||s.records.length!==Math.min(32,s.latest_seq))
    throw Error('Invalid USB burst schema');
  const out={version:1,available:s.available,window_us:1000,capacity:32};
  for(const k of totals)out[k]=s[k];
  out.arrival_hist=[...s.arrival_hist];
  out.records=s.records.map((r,i)=>{
    if(!r||!numbers.every(k=>uint(r[k]))||!booleans.every(k=>typeof r[k]==='boolean')||
      r.seq!==s.latest_seq-s.records.length+i+1||!r.full||r.full>r.submitted||
      r.window_us%1000||r.first_full_us<r.window_us||r.first_full_us>=r.window_us+1000||
      r.first_full_us>s.sampled_us||r.in_use>8||r.ncm_captured_us>s.sampled_us)
      throw Error('Invalid USB burst record');
    return Object.fromEntries([...numbers,...booleans].map(k=>[k,r[k]]));
  });
  if(s.full>s.submitted||s.arrival_hist.reduce((a,b)=>a+b,0)!==s.windows)
    throw Error('Invalid USB burst counters');
  return out;
}
export async function readBursts(board) {
  if(!board.bursts)return {available:false,reason:'unsupported'};
  try {
    const raw=await board.bursts();
    if(raw===null)return {available:false,reason:'unsupported'};
    return cleanBursts(raw);
  } catch { return {available:false,reason:'read/schema error'}; }
}
export function burstDelta(before,after) {
  const out={before,after,available:false,records:[],warnings:[]};
  if(!before.available||!after.available) {
    out.warnings.push('Burst diagnostics unavailable (firmware, allocation or API); not a clean test');
    return out;
  }
  const monotonic=['sampled_us','latest_seq','submitted','full','windows'];
  if(before.session_id!==after.session_id||monotonic.some(k=>after[k]<before[k])||
    after.arrival_hist.some((n,i)=>n<before.arrival_hist[i])) {
    out.warnings.push('Burst diagnostics reset; interval unknown');return out;
  }
  out.available=true;
  for(const k of ['submitted','full','windows'])out[k]=after[k]-before[k];
  out.arrival_hist=after.arrival_hist.map((n,i)=>n-before.arrival_hist[i]);
  out.new_windows=after.latest_seq-before.latest_seq;
  // The window containing the BEFORE snapshot may gain rejections without a
  // new sequence number. Keep its first-rejection state, explicitly marked old.
  for(const r of after.records) {
    const prior=before.records.find(b=>b.seq===r.seq);
    if(r.seq<before.latest_seq)continue;
    const full=r.full-(prior?.full||0);
    if(full<=0)continue;
    out.records.push({...r,interval_full:full,
      start_partial:r.window_us<before.sampled_us,
      end_partial:r.window_us+1000>after.sampled_us,
      snapshot_before_interval:r.first_full_us<before.sampled_us});
  }
  out.missing_windows=out.new_windows-out.records.filter(r=>r.seq>before.latest_seq).length;
  out.unrepresented_full=out.full-out.records.reduce((n,r)=>n+r.interval_full,0);
  if(out.missing_windows>0)out.warnings.push(`${out.missing_windows} new rejection windows overwritten in ring`);
  if(out.unrepresented_full>0)out.warnings.push(`${out.unrepresented_full} queue-full decisions lack retained detail`);
  if(out.unrepresented_full<0) {
    out.available=false;out.warnings.push('Inconsistent burst counters; interval unknown');out.records=[];
  }
  if(out.records.some(r=>r.start_partial||r.end_partial))out.warnings.push('Boundary windows are partial');
  if(out.records.some(r=>!r.ncm_available))out.warnings.push('Some NCM snapshots unavailable');
  return out;
}
export function burstMarkdown(records) {
  const batches=[...new Map(records.filter(r=>r.batch_bursts).map(r=>[r.id,r])).values()];
  if(!batches.length)return [];
  const lines=['','## USB queue-full bursts','',
    'Device-wide eligible submission decisions in fixed 1 ms windows, not physical packet arrival or flow-specific loss. The last nonempty histogram window closes on the next submission in a new window; boundary counts are not exact test-window arrival rates.',
    'PSRAM ring retains the latest 32 rejection windows. Read before/after each USB batch, not polled under load. Totals survive ring overwrite; missing detail is explicit. Instrumentation and snapshot requests add overhead.', '',
    '| Test | Eligible submissions | Full | Closed windows: 1–4 / 5–8 / 9–16 / ≥17 submissions | New full windows | Retained details | Missing full decisions | Notes |',
    '|---|---:|---:|---|---:|---:|---:|---|'];
  for(const r of batches) {
    const d=r.batch_bursts,v=k=>d.available?d[k]:'n/a';
    lines.push(`| ${r.id} | ${v('submitted')} | ${v('full')} | ${d.available?d.arrival_hist.join(' / '):'n/a'} | ${v('new_windows')} | ${d.available?d.records.length:'n/a'} | ${v('unrepresented_full')} | ${d.warnings.join('; ')} |`);
  }
  lines.push('', 'Up to three retained windows with most full decisions per batch (ties: oldest). This is not the worst three over the entire test if the ring overflowed. All retained records and both snapshots are in measurements.ndjson/result.json.',
    'State is from the first rejection in the window. Owned slots are not pending queue depth. NCM is a cached driver-event snapshot copied after unlocking the queue, not atomic with rejection; age and capture delay are shown. Worker age is since this send began, not ISR or bus latency.', '',
    '| Test / sequence | Board window ms | Submissions / interval full | Owned / active / waiting | Worker age µs | NCM free / ready / active | NCM age / capture delay µs | Partial boundary / old state |',
    '|---|---:|---|---|---:|---|---|---|');
  for(const r of batches)for(const b of [...r.batch_bursts.records].sort((a,b)=>b.interval_full-a.interval_full||a.seq-b.seq).slice(0,3)) {
    const age=b.ncm_available&&b.ncm_captured_us>=b.ncm_sampled_us?b.ncm_captured_us-b.ncm_sampled_us:'n/a';
    const delay=b.ncm_available?b.ncm_captured_us-b.first_full_us:'n/a';
    const worker=b.worker_active&&b.first_full_us>=b.worker_started_us?b.first_full_us-b.worker_started_us:'n/a';
    lines.push(`| ${r.id} / ${b.seq} | ${b.window_us/1000} | ${b.submitted} / ${b.interval_full} | ${b.in_use} / ${b.worker_active} / ${b.worker_waiting} | ${worker} | ${b.ncm_available?`${b.ncm_free} / ${b.ncm_ready} / ${b.ncm_active}`:'n/a'} | ${age} / ${delay} | ${b.start_partial||b.end_partial} / ${b.snapshot_before_interval} |`);
  }
  return lines;
}
