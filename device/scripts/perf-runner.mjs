#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { lookup } from 'node:dns/promises';
import { appendFile, mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { parseArgs, checked, command, iperfArgs, parseIperf, parsePing, stats,
  summarize, measurementPlan, counterDelta, usbCounterFields, ncmCounterFields, usbQueueCounterFields, hasPingProblem, summarizeUsbDownSweep } from './perf-lib.mjs';
import { discoverBoard, checkRoute, sshArgs, startServers } from './perf-network.mjs';
import { prepareIperfBinding, iperfEnvironment, verifyIperfBinding, iperfError } from './perf-bind.mjs';

const root=fileURLToPath(new URL('../../',import.meta.url));
const help=`Usage: npm run device:perf -- [user@]SERVER[:SSH_PORT] [options]

macOS runner; connect the selected paths: USB and/or Mac Wi-Fi to the board AP.
The USB download sweep requires USB only, not a Mac Wi-Fi connection to the AP.
SSH must already work with a key/agent and a verified known_hosts entry.
Required: local/remote iperf3, remote python3, Apple Command Line Tools. Nothing is installed automatically.

  --quick                 Smoke test: 3s, 2 measured repeats, no soak
  --usb-down-sweep        USB UDP download 5..10M, 15s x 3 per rate (~7 min)
  --paths auto|usb|ap|both Auto detects paths; 'both' requires USB + AP
  --seconds N             Per throughput test (default 30)
  --runs N                Measured repeats, excluding warm-up (default 5)
  --soak-minutes N         Load/idle endurance stage (default 30; 0 disables)
  --idle-seconds N         Baseline/final idle periods (default 30)
  --iperf-port N           First data port (default 5201; second is N+1)
  --server-ip IPv4         Data destination if different from SSH hostname
  --admin-url URL          Override discovery, e.g. http://192.168.7.1/
  --admin-ca cert.pem      Trust the device HTTPS certificate
  --admin-insecure         Explicitly skip HTTPS certificate verification
  --out DIRECTORY         Parent for a unique result directory

Admin password: MESHPN_ADMIN_PASSWORD environment variable (default: admin).
Close the admin browser tab: its Wi-Fi scan/session can disrupt the test.
Full USB+AP run: ~75 min, potentially several GB. --quick: ~3 min.
USB download sweep: npm run device:perf:usb-down -- SERVER[:SSH_PORT]
USB only; 3s warm-up per rate, 3s recovery gaps, no upload/AP/soak tests.
Do not combine the sweep with --quick or conflicting timing/path options.
Ctrl-C saves partial results and stops only this runner's remote servers.
Report: device/perf-results/<timestamp>-<random>/report.md + JSON/raw logs.
`;

// Dependency injection keeps the complete schedule testable without real networking or waits.
export async function executeSchedule(o, paths, {batch,idle,now=Date.now,check=()=>{}}) {
  if(o.usbDownSweep) {
    const plan=measurementPlan(paths,o);
    await idle('baseline-idle',o.idleSeconds);
    for(const [index,test] of plan.entries()) {
      check();await batch(test);
      if(index<plan.length-1)await idle(`sweep-recovery-${index+1}`,3);
    }
    await idle('final-idle',o.idleSeconds);
    return;
  }
  for(const direction of ['up','down']) {
    for(const p of paths)await batch({paths:[p],protocol:'tcp',direction,seconds:o.seconds,phase:'warmup',warmup:true,run:0});
  }
  await idle('baseline-idle',o.idleSeconds);
  for(const test of measurementPlan(paths,o)){check();await batch(test);}
  const deadline=now()+o.soakMinutes*60000;
  let cycle=0;
  while(now()<deadline) {
    check();cycle++;
    const cycleEnd=Math.min(deadline,now()+900000),loadEnd=now()+(cycleEnd-now())*2/3;
    let run=0;
    while(now()+1000<=loadEnd) {
      check();await batch({paths,protocol:'tcp',direction:run%2?'down':'up',seconds:Math.min(60,Math.floor((loadEnd-now())/1000)),
        phase:`soak-${cycle}`,warmup:false,run:++run});
    }
    await idle(`soak-${cycle}-idle`,Math.max(0,(cycleEnd-now())/1000));
  }
  await idle('final-idle',o.idleSeconds);
}

export function cleanStatus(s) {
  // Allowlist: never dump login responses, tokens, environment, or future VPN credentials.
  const pick=(v,keys)=>Object.fromEntries(keys.filter(k=>v?.[k]!==undefined).map(k=>[k,v[k]]));
  return {...pick(s,['board','build','idf','uptime_sec','temperature_c','https_enabled']),
    wifi:pick(s.wifi,['connected','scanning','state','ip','rssi','disconnect_reason']),
    net:pick(s.net,['usb_ip','ap_ip','ap_active','ap_clients','ap_channel','usb_napt','ap_napt','ap_ip4_rx','lan_ip4_rx']),
    usb:{...pick(s.usb,['profile','host_ready','tx_mode',...usbCounterFields,'tx_attempts_max','tx_wait_max_us']),
      tx_queue:pick(s.usb?.tx_queue,['enabled',...usbQueueCounterFields,'capacity','max_age_ms','pending','in_use','high_water',
        'worker_active','event_wait','queue_wait_max_us','residence_max_us']),
      ncm:pick(s.usb?.ncm,['available',...ncmCounterFields,'sampled_us','sample_age_ms','pool','free','ready',
        'glue','active','glue_frames','max_ntb','max_datagrams','free_min','ready_max','completion_max_us','backlog_gap_max_us'])},
    memory:Object.fromEntries(['internal','dma','psram'].map(k=>[k,pick(s.memory?.[k],['total','free','minimum_free','largest_block'])])),
    cpu:{...pick(s.cpu,['available','sampled_us','sample_age_ms','interval_ms','collection_us']),
      cores:(s.cpu?.cores||[]).map(c=>pick(c,['id','load_pct'])),
      tasks:(s.cpu?.tasks||[]).map(t=>pick(t,['id','name','core','priority','stack_free','runtime_us','load_pct']))}};
}

export function telemetrySummary(samples) {
  const good=samples.filter(s=>s.status),events=[];
  let previous,epoch=0;
  const uniqueCPU=new Map();
  for(const s of good) {
    const v=s.status;
    if(previous&&v.uptime_sec<previous.uptime_sec){events.push({time:s.time,event:'uptime decreased: possible reboot'});epoch++;}
    if(v.wifi.connected===false)events.push({time:s.time,event:'STA disconnected'});
    if(v.wifi.scanning===true)events.push({time:s.time,event:'Wi-Fi scan during measurements'});
    if(previous?.usb.host_ready===true&&v.usb.host_ready===false)events.push({time:s.time,event:'USB host disconnected'});
    if(previous?.net.ap_active===true&&v.net.ap_active===false)events.push({time:s.time,event:'AP stopped'});
    if(v.usb.tx_queue?.enabled===false&&v.usb.tx_queue.init_failed>0&&
       !(previous?.usb.tx_queue?.enabled===false&&previous.usb.tx_queue.init_failed>0))
      events.push({time:s.time,event:'USB TX queue initialization failed: synchronous fallback'});
    if(v.cpu.available&&Number.isFinite(v.cpu.sampled_us)&&Number.isFinite(v.cpu.sample_age_ms)&&v.cpu.sample_age_ms<=5000)
      uniqueCPU.set(`${epoch}/${v.cpu.sampled_us}`,v.cpu);
    previous=v;
  }
  const cpu=[...uniqueCPU.values()];
  const idleMemory=phase=>{
    const group=good.filter(s=>s.phase===phase),last=group.at(-1);
    // Only the tail of equal-duration idle windows; not historical minimum_free.
    const tail=group.filter(s=>last&&s.elapsed_ms>=last.elapsed_ms-10000);
    return Object.fromEntries(['internal','dma','psram'].map(k=>[k,{
      free:stats(tail.map(s=>s.status.memory[k]?.free)),largest_block:stats(tail.map(s=>s.status.memory[k]?.largest_block))}]));
  };
  return {samples:good.length,api_errors:samples.length-good.length,events,
    counter_delta:counterDelta(epoch?null:good[0]?.status,good.at(-1)?.status),
    ncm_last:good.at(-1)?.status.usb.ncm,
    usb_queue_last:good.at(-1)?.status.usb.tx_queue,
    temperature_c:stats(good.map(s=>s.status.temperature_c)),rssi:stats(good.map(s=>s.status.wifi.rssi)),
    cpu_samples:cpu.length,cpu_load:Object.fromEntries([0,1].map(id=>[id,stats(cpu.map(c=>c.cores.find(v=>v.id===id)?.load_pct))])),
    cpu_collection_us:stats(cpu.map(c=>c.collection_us)),
    baseline_idle_memory:idleMemory('baseline-idle'),final_idle_memory:idleMemory('final-idle')};
}

export function reportMarkdown(result) {
  const fmt=v=>Number.isFinite(v)?v.toFixed(2):'n/a';
  const lines=['# MeshPN performance report','',`Result: **${result.outcome}**`,
    `Started: ${result.started}; ended: ${result.ended}`,`Server: ${result.serverIP||'unresolved'}; SSH: ${result.target}`,
    `Checkout: ${result.git?.commit||'unknown'}${result.git?.dirty?' (dirty)':''}; board build: ${result.board?.build||'unknown'}`,'',
    'up = Mac → server; down = server → Mac. Throughput is measured at the receiver. Warm-ups excluded.',
    'WAN servers include ISP/network limits. Percentiles across a few repetitions are only indicative.','',
    '| Scenario/path/protocol/direction/rate | n | Mbit/s min | median | p95 | max | UDP loss % median | jitter ms median | TCP retransmits median | failed |',
    '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|'];
  for(const [name,g] of Object.entries(result.summary||{}))lines.push(`| ${name} | ${g.mbps?.count||0} | ${fmt(g.mbps?.min)} | ${fmt(g.mbps?.median)} | ${fmt(g.mbps?.p95)} | ${fmt(g.mbps?.max)} | ${fmt(g.loss?.median)} | ${fmt(g.jitter?.median)} | ${fmt(g.retransmits?.median)} | ${g.failed} |`);
  if(result.options?.usbDownSweep) {
    lines.push('', '## USB download rate sweep', '',
      'Measured runs only. Sender/receiver are achieved rates, not the requested UDP target. Missing sender statistics remain n/a.',
      'Queue losses include ALL queue rejection/send-failure stages, not usb.tx_dropped again. Device-wide batch counters include admin traffic; missing/reset windows remain n/a.',
      'Ping p95 = median of per-test p95 values (not a pooled percentile). Residence includes queue wait and sync send, not host delivery. Three repeats and WAN limits do not establish a hard loss-free threshold.', '',
      '| Target Mbit/s | n / failed | Sender median | Receiver median | UDP loss % median / max | Queue full | All queue losses / % | Residence mean ms | Ping n | Ping p95 ms | Ping loss % max |',
      '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|');
    for(const s of summarizeUsbDownSweep(result.records||[],result.pings||[]))
      lines.push(`| ${s.rate} | ${s.n} / ${s.failed} | ${fmt(s.sender_mbps?.median)} | ${fmt(s.receiver_mbps?.median)} | ${fmt(s.udp_loss?.median)} / ${fmt(s.udp_loss?.max)} | ${s.full??'n/a'} | ${s.queue_losses??'n/a'} / ${fmt(s.queue_loss_percent)} | ${fmt(s.residence_mean_ms)} | ${s.ping_samples} | ${fmt(s.ping_p95_ms?.median)} | ${fmt(s.ping_loss?.max)} |`);
  }
  lines.push('','## Ping latency (per test, including idle)','',
    '| Test | Path | median ms | p95 ms | loss % | error |','|---|---|---:|---:|---:|---|');
  for(const p of result.pings||[])lines.push(`| ${p.id} | ${p.path} | ${fmt(p.rtt_ms?.median)} | ${fmt(p.rtt_ms?.p95)} | ${fmt(p.loss_percent)} | ${(p.error||'').replaceAll('|','/').replaceAll('\n',' ')} |`);
  const t=result.telemetry;
  if(t) {
    lines.push('','## Board telemetry','',`Samples: ${t.samples}; API errors: ${t.api_errors}; unique CPU samples: ${t.cpu_samples}.`,
      `Temperature median/max: ${fmt(t.temperature_c?.median)}/${fmt(t.temperature_c?.max)} °C.`,
      ...[0,1].map(id=>`CPU${id} median/p95/max: ${fmt(t.cpu_load[id]?.median)}/${fmt(t.cpu_load[id]?.p95)}/${fmt(t.cpu_load[id]?.max)}%.`),
      '', '| Memory (bytes, idle medians) | Free before | Free after | Largest block before | Largest block after |', '|---|---:|---:|---:|---:|');
    for(const k of ['internal','dma','psram'])lines.push(`| ${k} | ${fmt(t.baseline_idle_memory[k].free?.median)} | ${fmt(t.final_idle_memory[k].free?.median)} | ${fmt(t.baseline_idle_memory[k].largest_block?.median)} | ${fmt(t.final_idle_memory[k].largest_block?.median)} |`);
    lines.push('','Two idle windows do not prove absence/presence of a leak. Historical minimum_free remains in status.ndjson. Internal and DMA overlap; do not add them.',
      '',`Detected events: ${t.events.length}. Details in result.json; short flaps/reboots between polls may be missed.`,
      '', '| Counter | Delta across run |', '|---|---:|',
      ...Object.entries(t.counter_delta).map(([k,v])=>`| ${k} | ${v??'n/a (missing/reset)'} |`));
    lines.push('', 'USB counters: tx_ok = accepted by USB stack, not confirmed host delivery. tx_retried = accepted after retry (not loss).',
      'Failed sync calls = tx_dropped + tx_timeout + tx_no_host. tx_dropped breakdown = tx_busy_exhausted + tx_no_mem + tx_invalid_state + tx_other_error.',
      'tx_busy counts rejected attempts, not packets or NTB occupancy. tx_wait_* measures whole TX calls (including failures), not bus completion; histogram buckets are disjoint.',
      'Lifetime maxima are retained in status.ndjson; they are not per-test maxima. Missing fields on older firmware remain n/a.');
    const q=t.usb_queue_last;
    if(q?.enabled)lines.push('',
      `USB TX worker queue: capacity=${q.capacity}, in_use=${q.in_use}, pending=${q.pending}, active=${q.worker_active}, lifetime high_water=${q.high_water}; pre-send expiry=${q.max_age_ms} ms.`,
      `NCM completion wait: ${q.event_wait===true?'enabled (25ms capacity budget)':q.event_wait===false?'disabled':'unknown (older firmware)'}. Capacity timeouts are included in usb.tx_timeout and queue.send_failed; do not add again. Wakeups are hints to retry, not buffer reservations.`,
      'Queue mode: usb.tx_* counts sync sends from the worker, NOT all lwIP submissions. tx_wait excludes queue residence. Queue rejects/expiry/stale frames must be inspected separately.',
      'Queue losses = full + no_host + invalid_length + not_ready + enqueue_failed + expired + stale + send_failed. send_failed overlaps usb sync-failure counters: do not add twice.',
      'enqueued means owned copy accepted, sent means accepted by TinyUSB; neither confirms delivery to the host application.');
    else if(q?.init_failed)lines.push('', 'WARNING: USB TX queue initialization failed; firmware is using the synchronous fallback.');
    const n=t.ncm_last;
    if(n?.available)lines.push('',
      `NCM last event snapshot: pool=${n.pool}; free=${n.free}; ready=${n.ready}; active=${n.active}; glue=${n.glue}; age=${fmt(n.sample_age_ms)} ms.`,
      `NCM lifetime observed free minimum=${n.free_min}, ready maximum=${n.ready_max}; last negotiated NTB limit=${n.max_ntb} bytes / ${n.max_datagrams} datagrams.`,
      'Occupancy is sampled at driver events, not time-weighted utilization. Gauges may be stale while idle; lifetime extrema are not per-run deltas.');
  }
  const usbBatches=new Map();
  for(const r of result.records||[])if(r.batch_counters&&!usbBatches.has(r.id))usbBatches.set(r.id,r);
  if(usbBatches.size) {
    lines.push('', '## USB TX by batch', '',
      'Device-wide deltas, including warm-ups and admin traffic. Combined batches appear once, not once per path. Wait = whole transmit call, not bus completion.', '',
      '| Test | Scenario | Accepted | Retried OK | Dropped | Timeout | No host | Busy attempts | TX mean ms | TX >25ms |',
      '|---|---|---:|---:|---:|---:|---:|---:|---:|---:|');
    for(const r of usbBatches.values()) {
      const d=r.batch_counters, v=k=>d[`usb.${k}`]??'n/a';
      const calls=d['usb.tx_calls'],us=d['usb.tx_wait_us'];
      const mean=Number.isFinite(calls)&&calls>0&&Number.isFinite(us)?us/calls/1000:null;
      const peers=(result.records||[]).filter(p=>p.id===r.id).map(p=>p.path).join('+');
      lines.push(`| ${r.id} | ${r.phase}/${peers}/${r.protocol}/${r.direction}${r.rate?`/${r.rate}M`:''} | ${v('tx_ok')} | ${v('tx_retried')} | ${v('tx_dropped')} | ${v('tx_timeout')} | ${v('tx_no_host')} | ${v('tx_busy')} | ${fmt(mean)} | ${v('tx_wait_gt_25ms')} |`);
    }
    if([...usbBatches.values()].some(r=>Number.isFinite(r.batch_counters['usb.ncm.ntb_started']))) {
      lines.push('', '## NCM transfers by batch', '',
        'Device → host only. NTB bytes include NCM headers/padding; completion time includes bus and TinyUSB event handling, not application delivery or isolated ISR latency.',
        'Backlog gap = processed NTB completion → next successful NTB submission when frames were already queued. Includes intervening ZLP; not pure endpoint idle time.', '',
        '| Test | NTB started | Bytes/NTB | Frames/NTB | Busy, no free | Completion mean ms | Backlog gap mean ms | Start / completion errors |',
        '|---|---:|---:|---:|---:|---:|---:|---:|');
      for(const r of usbBatches.values()) {
        const d=r.batch_counters,v=k=>d[`usb.ncm.${k}`];
        const mean=(sum,count,scale=1)=>Number.isFinite(v(sum))&&Number.isFinite(v(count))&&v(count)>0?fmt(v(sum)/v(count)/scale):'n/a';
        lines.push(`| ${r.id} | ${v('ntb_started')??'n/a'} | ${mean('bytes_started','ntb_started')} | ${mean('frames_started','ntb_started')} | ${v('busy_no_free')??'n/a'} | ${mean('completion_us','completion_timed',1000)} | ${mean('backlog_gap_us','backlog_gaps',1000)} | ${v('start_errors')??'n/a'} / ${v('completion_errors')??'n/a'} |`);
      }
    }
    if([...usbBatches.values()].some(r=>r.batch_counters['usb.tx_queue.submitted']>0)) {
      lines.push('', '## USB TX queue by batch', '',
        'Means describe frames completed in the counter window, possibly enqueued earlier. Includes admin traffic; combined batches appear once.', '',
        '| Test | Enqueued | Sent | Full | Expired | Stale | Send failed | Queue wait mean ms | Residence mean ms | Capacity waits | Capacity timeouts | Capacity wait mean ms |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|');
      for(const r of usbBatches.values()) {
        const v=k=>r.batch_counters[`usb.tx_queue.${k}`];
        const mean=k=>Number.isFinite(v(k))&&Number.isFinite(v('completed'))&&v('completed')>0?fmt(v(k)/v('completed')/1000):'n/a';
        const capacityMean=Number.isFinite(v('capacity_wait_us'))&&v('capacity_waits')>0?fmt(v('capacity_wait_us')/v('capacity_waits')/1000):'n/a';
        lines.push(`| ${r.id} | ${v('enqueued')??'n/a'} | ${v('sent')??'n/a'} | ${v('full')??'n/a'} | ${v('expired')??'n/a'} | ${v('stale')??'n/a'} | ${v('send_failed')??'n/a'} | ${mean('queue_wait_us')} | ${mean('residence_us')} | ${v('capacity_waits')??'n/a'} | ${v('capacity_timeouts')??'n/a'} | ${capacityMean} |`);
      }
    }
  }
  lines.push('','## Warnings / omissions','',...(result.warnings||[]).map(s=>`- ${s}`),
    '- Physical USB reconnect, router reboot, sleep/resume, AP-disabled baseline and STA-side admin isolation are not automated; runner does not change device/network settings.',
    '- DHCP was inspected and routes checked; this is not a DHCP renewal or DNS/mDNS test. No serial watchdog log is collected.',
    '- HT20/HT40 negotiation is not currently exposed by the API.');
  if(result.error)lines.push('',`Error: ${result.error}`);
  return lines.join('\n')+'\n';
}

export async function main(args=process.argv.slice(2), dependencies={}) {
  const runtime={platform:process.platform,command,checked,lookup,discoverBoard,checkRoute,startServers,prepareIperfBinding,spawn,delay,...dependencies};
  const o=parseArgs(args);
  if(o.help){console.log(help);return 0;}
  if(runtime.platform!=='darwin')throw Error('This runner currently supports macOS hosts (USB + Wi-Fi interface-scoped routes). The SSH server may run Linux or macOS.');
  const controller=new AbortController(),signal=controller.signal;
  const abort=()=>controller.abort();
  process.once('SIGINT',abort);process.once('SIGTERM',abort);
  let output,servers,caffeine,samplerDone,samplerStop=false,wakeSampler,samplerError;
  const started=Date.now(),samples=[],records=[],pings=[];
  let phase='preflight',sequence=0,board;
  const result={schema:1,started:new Date(started).toISOString(),target:o.target,options:o,
    host:{platform:runtime.platform,release:os.release(),arch:process.arch,node:process.version},records,pings,warnings:[],outcome:'failed'};
  const log=runtime.log||(s=>console.log(`[${new Date().toLocaleTimeString()}] ${s}`));
  const check=()=>{if(signal.aborted)throw Error('Interrupted');servers?.assertAlive();};
  try {
    const parent=path.resolve(o.out||path.join(root,'device/perf-results'));
    await mkdir(parent,{recursive:true});
    output=await mkdtemp(path.join(parent,new Date(started).toISOString().replaceAll(':','-')+'-'));
    log(`Results: ${output}`);
    let localVersion;
    try {localVersion=await runtime.checked('iperf3',['--version'],{signal});}
    catch{throw Error('Local iperf3 missing/not runnable. Install on Mac: brew install iperf3');}
    const binding=await runtime.prepareIperfBinding(output,signal);
    result.binding='macOS IP_BOUND_IF (process-local socket helper)';
    const remoteCheck="command -v iperf3 >/dev/null || { echo 'MISSING_IPERF3' >&2; exit 41; }; command -v python3 >/dev/null || { echo 'MISSING_PYTHON3' >&2; exit 42; }; iperf3 --version; python3 --version";
    const remote=await runtime.command('ssh',[...sshArgs(o),remoteCheck],{signal,timeout:20000});
    if(remote.code!==0)throw Error(`SSH prerequisites failed: ${remote.stderr.trim()}. Server Debian/Ubuntu: sudo apt-get install iperf3 python3; Fedora: sudo dnf install iperf3 python3; macOS: brew install iperf3 python. SSH must work without prompts; first verify its host key using ssh -p ${o.sshPort} ${o.sshTarget}.`);
    result.versions={localIperf:localVersion.trim(),remote:remote.stdout.trim()};
    try {result.git={commit:(await runtime.checked('git',['-C',root,'rev-parse','HEAD'])).trim(),dirty:Boolean((await runtime.checked('git',['-C',root,'status','--porcelain'])).trim())};}catch{}
    result.serverIP=o.serverIP||(await runtime.lookup(o.host,{family:4})).address;
    board=await runtime.discoverBoard(o,signal,log);
    result.paths=board.paths;result.board=cleanStatus(board.initial);
    for(const p of board.paths) {
      log(`${p.kind.toUpperCase()}: ${p.iface} ${p.address} → ${p.gateway} → ${result.serverIP}`);
      await writeFile(path.join(output,`route-${p.kind}.txt`),await runtime.checkRoute(p,result.serverIP,signal));
    }
    for(const kind of ['usb','ap'])if(!board.paths.some(p=>p.kind===kind))result.warnings.push(`${kind.toUpperCase()} not selected/connected; its single and combined tests were skipped.`);
    if(o.soakMinutes===0)result.warnings.push('Endurance stage disabled.');
    if(o.adminInsecure)result.warnings.push('HTTPS certificate verification explicitly disabled.');
    const plan=measurementPlan(board.paths,o);
    const estimated=(plan.reduce((sum,t)=>sum+t.seconds,0)+(o.usbDownSweep?(plan.length-1)*3:board.paths.length*2*o.seconds)+2*o.idleSeconds)/60+o.soakMinutes;
    if(estimated>240)throw Error('Requested suite exceeds 4 hours; reduce --runs/--seconds/--soak-minutes (remote safety deadline is 6 hours).');
    log(`Estimated load/idle time: ${Math.ceil(estimated)} min + process overhead. Close admin UI; keep Mac connected.`);
    caffeine=runtime.spawn('/usr/bin/caffeinate',['-i','-m','-s','-w',String(process.pid)],{stdio:'ignore'});
    caffeine.on('error',()=>result.warnings.push('Could not inhibit Mac sleep; keep the host awake.'));
    servers=await runtime.startServers(o,board.paths.length,signal);
    const sample=async()=>{
      const s={time:new Date().toISOString(),elapsed_ms:Date.now()-started,phase};
      try{s.status=cleanStatus(await board.status());}catch(e){s.error=e.message;}
      samples.push(s);await appendFile(path.join(output,'status.ndjson'),JSON.stringify(s)+'\n');return s.status;
    };
    samplerDone=(async()=>{
      while(!samplerStop&&!signal.aborted) {
        const tick=Date.now();await sample();
        if(!samplerStop&&!signal.aborted)await new Promise(resolve=>{
          const timer=setTimeout(resolve,Math.max(0,2000-(Date.now()-tick)));
          wakeSampler=()=>{clearTimeout(timer);resolve();};
        });
      }
    })();
    // Attach immediately so a disk failure during a long iperf run is never unhandled.
    samplerDone.catch(e=>{samplerError=e;controller.abort();});
    const ping=async(p,seconds,id)=>{
      const record={id,path:p.kind};
      try {
        const r=await runtime.command('/sbin/ping',['-n','-b',p.iface,'-S',p.address,'-i','0.2','-c',String(Math.max(1,Math.ceil(seconds*5))),'-t',String(Math.max(1,Math.ceil(seconds))),result.serverIP],{signal,timeout:seconds*1000+5000});
        await writeFile(path.join(output,`${id}-${p.kind}.ping.txt`),r.stdout+'\n'+r.stderr);
        Object.assign(record,parsePing(r.stdout));
        if(!record.rtt_ms||record.loss_percent===null)record.error=`Ping unavailable (exit ${r.code}); server may block ICMP: ${r.stderr.trim()}`;
      }catch(e){record.error=e.message;}
      pings.push(record);return record;
    };
    const batch=async test=>{
      check();
      const id=String(++sequence).padStart(4,'0');phase=`${id}-${test.phase}-${test.protocol}-${test.direction}${test.warmup?'-warmup':''}`;
      log(`${phase}: ${test.paths.map(p=>p.kind).join('+')}${test.rate?` ${test.rate} Mbit/s`:''}, ${test.seconds}s`);
      for(const p of test.paths)await runtime.checkRoute(p,result.serverIP,signal);
      const before=await sample();
      const measured=await Promise.all(test.paths.map(async p=>{
        const r={id,phase:test.phase,path:p.kind,protocol:test.protocol,direction:test.direction,rate:test.rate??null,
          seconds:test.seconds,run:test.run,warmup:test.warmup,started:new Date().toISOString()};
        const client=async()=>{
          let raw;
          try {
            const args=iperfArgs(result.serverIP,servers.ports[board.paths.indexOf(p)],p,test);
            r.command=['iperf3',...args];
            raw=await runtime.command('iperf3',args,{signal,timeout:(test.seconds+20)*1000,
              env:iperfEnvironment(binding,p.iface)});
            await writeFile(path.join(output,`${id}-${p.kind}.iperf.json`),raw.stdout);
            await writeFile(path.join(output,`${id}-${p.kind}.stderr.txt`),raw.stderr);
            if(raw.code!==0)throw Error(`iperf3 exited ${raw.code}: ${iperfError(raw)}`);
            verifyIperfBinding(raw.stderr,p.iface);
            Object.assign(r,parseIperf(raw.stdout,test.protocol));
            if(r.local_address!==p.address)throw Error(`Unexpected source ${r.local_address}; expected ${p.address}`);
            await runtime.checkRoute(p,result.serverIP,signal);
          }catch(e){
            r.error=e.message;
            if(!raw) {
              await writeFile(path.join(output,`${id}-${p.kind}.iperf.json`),e.stdout||'');
              await writeFile(path.join(output,`${id}-${p.kind}.stderr.txt`),e.stderr||e.message);
            }
          }
          r.ended=new Date().toISOString();return r;
        };
        await Promise.all([client(),ping(p,test.seconds,id)]);
        return r;
      }));
      const after=await sample(),deltas=counterDelta(before,after);
      // Counters describe the entire batch, not each path separately in a combined test.
      for(const r of measured) {
        r.batch_counters=deltas;records.push(r);
        await appendFile(path.join(output,'measurements.ndjson'),JSON.stringify(r)+'\n');
        log(`${r.path}: ${r.error?'FAILED: '+r.error:r.mbps.toFixed(2)+' Mbit/s'}`);
      }
      check();
      if(test.phase==='preflight'&&measured.some(r=>r.error))throw Error('Preflight failed; inspect raw JSON/stderr. Check interface binding, macOS Local Network permission, server TCP/UDP data ports and firewall. No firewall/route changes were made.');
    };
    const idle=async(name,seconds)=>{
      check();phase=name;log(`${name}: ${Math.round(seconds)}s`);
      const id=String(++sequence).padStart(4,'0');await sample();
      await Promise.all([runtime.delay(seconds*1000,undefined,{signal}),...board.paths.map(p=>ping(p,seconds,id))]);
      await sample();check();
    };
    // Fail fast on both directions/protocols before spending an hour on a broken setup.
    for(const p of board.paths)for(const protocol of ['tcp','udp'])for(const direction of (o.usbDownSweep?['down']:['up','down']))
      await batch({paths:[p],protocol,direction,rate:protocol==='udp'?5:null,seconds:1,phase:'preflight',warmup:true,run:0});
    await executeSchedule(o,board.paths,{batch,idle,check});
    if(samplerError)throw samplerError;
    result.outcome=records.some(r=>r.error)?'failed':'completed';
  }catch(e){
    result.error=e.message;result.outcome=signal.aborted?'interrupted':'failed';
    if(e.boardInitial)result.board=cleanStatus(e.boardInitial);
    if(e.discovery){result.discovery=e.discovery;result.paths=e.discovery.detectedPaths;}
  }
  finally {
    samplerStop=true;wakeSampler?.();
    if(samplerDone)await samplerDone.catch(e=>{result.error=e.message;result.outcome='failed';});
    if(servers)await servers.close().catch(e=>{result.warnings.push(`Server cleanup: ${e.message}`);result.outcome='failed';});
    caffeine?.kill('SIGTERM');process.removeListener('SIGINT',abort);process.removeListener('SIGTERM',abort);
    result.ended=new Date().toISOString();result.summary=summarize(records);result.telemetry=telemetrySummary(samples);
    if(o.usbDownSweep)result.usb_down_sweep=summarizeUsbDownSweep(records,pings);
    if(!result.telemetry.cpu_samples&&samples.length) {
      result.warnings.push('No valid CPU runtime samples; CPU-load results unavailable.');
      if(result.outcome==='completed')result.outcome='completed-with-warnings';
    }
    if(result.telemetry.api_errors||result.telemetry.events.length||hasPingProblem(pings)) {
      result.warnings.push('Telemetry/link/ping problems (including ping packet loss) detected; inspect result.json and raw logs.');
      if(result.outcome==='completed')result.outcome='completed-with-warnings';
    }
    if(output) {
      await writeFile(path.join(output,'result.json'),JSON.stringify(result,null,2)+'\n');
      await writeFile(path.join(output,'report.md'),reportMarkdown(result));
      log(`${result.outcome}: ${path.join(output,'report.md')}`);
    }
  }
  if(result.error)console.error(result.error);
  return result.outcome==='completed'?0:result.outcome==='completed-with-warnings'?2:signal.aborted?130:1;
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  main().then(code=>{process.exitCode=code;}).catch(e=>{console.error(e.message);process.exitCode=1;});
}
