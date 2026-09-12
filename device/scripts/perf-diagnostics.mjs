import { counterDelta } from './perf-lib.mjs';

// Times are when Node observes ping output, not packet capture/send timestamps.
export function pingEvent(line, observedMs) {
  const seq=/icmp_seq[= ](\d+)/.exec(line);
  if(!seq)return null;
  const reply=/time[=<]([\d.]+)\s*ms/.exec(line);
  const timeout=/Request timeout/i.test(line);
  if(!reply&&!timeout)return null;
  return {time:new Date(observedMs).toISOString(),kind:reply?'reply':'timeout',
    sequence:Number(seq[1]),rtt_ms:reply?Number(reply[1]):null};
}

// Correlation, not attribution. HTTP polls and ping output are not synchronized
// packet captures; preserve the actual bracket and never invent missing deltas.
export function blackoutDiagnostics(records,pings,samples) {
  const out=[];
  const good=samples.filter(s=>s.status&&Number.isFinite(Date.parse(s.time)))
    .sort((a,b)=>Date.parse(a.time)-Date.parse(b.time));
  for(const r of records)for(const z of r.timing?.zero_receive_intervals||[]) {
    if(z.seconds<0.5)continue;
    // Remote receiver clocks need synchronization we do not have.
    const anchor=r.timing.receiver_interval_source==='client'?r.timing.client_timestamp_ms:null;
    const row={id:r.id,path:r.path,interval:z,alignment:'unknown',board:null,server:null,telemetry:null};
    out.push(row);
    if(!Number.isFinite(anchor))continue;
    const start=anchor+z.start*1000,end=anchor+z.end*1000;
    row.alignment='approximate client iperf timestamp; ±1s context';
    row.start=new Date(start).toISOString();row.end=new Date(end).toISOString();
    for(const target of ['board','server']) {
      const ping=pings.find(p=>p.id===r.id&&p.path===r.path&&(p.target||'server')===target);
      if(!ping)continue;
      const events=(ping.events||[]).filter(e=>Date.parse(e.time)>=start-1000&&Date.parse(e.time)<=end+1000);
      row[target]={replies:events.filter(e=>e.kind==='reply').length,
        timeouts:events.filter(e=>e.kind==='timeout').length,events,probe_error:ping.error||null};
    }
    const before=good.filter(s=>Date.parse(s.finished||s.time)<=start).at(-1);
    const after=good.find(s=>Date.parse(s.time)>=end);
    const errors=samples.filter(s=>s.error&&Date.parse(s.time)<=end+1000&&Date.parse(s.finished||s.time)>=start-1000);
    const observations=good.filter(s=>Date.parse(s.time)<=end+1000&&Date.parse(s.finished||s.time)>=start-1000)
      .map(s=>({time:s.time,finished:s.finished,wifi:s.status.wifi,usb_host_ready:s.status.usb?.host_ready}));
    row.telemetry={observations,api_errors:errors.map(s=>({time:s.time,finished:s.finished,error:s.error})),
      before:before?{time:before.time,finished:before.finished,uptime_sec:before.status.uptime_sec}:null,
      after:after?{time:after.time,finished:after.finished,uptime_sec:after.status.uptime_sec}:null,
      counters:before&&after&&start-Date.parse(before.time)<=10000&&Date.parse(after.finished||after.time)-end<=10000?
        counterDelta(before.status,after.status):null};
  }
  return out;
}
