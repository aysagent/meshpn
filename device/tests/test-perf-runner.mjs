import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import http from 'node:http';
import net from 'node:net';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { parseArgs, quote, command, iperfArgs, parseIperf, stats, parsePing, summarize,
  measurementPlan, counterDelta, macRoute, sameSubnet, remoteServer, ncmCounterFields, usbQueueCounterFields, hasPingProblem, summarizeUsbDownSweep } from '../scripts/perf-lib.mjs';
import { discoverBoard, checkRoute, requestBoard, sshArgs } from '../scripts/perf-network.mjs';
import { prepareIperfBinding, macosBuildContext, iperfEnvironment, verifyIperfBinding, iperfError } from '../scripts/perf-bind.mjs';
import { executeSchedule, cleanStatus, telemetrySummary, reportMarkdown, main } from '../scripts/perf-runner.mjs';
import { pingEvent, blackoutDiagnostics } from '../scripts/perf-diagnostics.mjs';

test('observed ping events parse Mac replies/timeouts, not summaries or missing packets',()=>{
  const now=1789246166000;
  assert.deepEqual(pingEvent('Request timeout for icmp_seq 12',now),
    {time:new Date(now).toISOString(),kind:'timeout',sequence:12,rtt_ms:null});
  assert.equal(pingEvent('64 bytes from 192.168.7.1: icmp_seq=13 ttl=64 time=1.2 ms',now).rtt_ms,1.2);
  assert.equal(pingEvent('2 packets transmitted, 0 packets received, 100% packet loss',now),null);
  assert.equal(pingEvent('PING 192.168.7.1',now),null);
});

test('blackout correlation uses distinct targets and real poll brackets; missing/remote/reset remain unknown',()=>{
  const base=1789246166000,iso=s=>new Date(base+s*1000).toISOString();
  const record={id:'0008',path:'usb',timing:{client_timestamp_ms:base,receiver_interval_source:'client',
    zero_receive_intervals:[{start:10,end:11,seconds:1}]}};
  const pings=[{id:'0008',path:'usb',target:'board',events:[pingEvent('icmp_seq=1 time=1 ms',base+10500)]},
    {id:'0008',path:'usb',target:'server',events:[pingEvent('Request timeout for icmp_seq 1',base+11000)]},
    {id:'0009',path:'usb',target:'board',events:[pingEvent('Request timeout for icmp_seq 1',base+11000)]}];
  const state=n=>({uptime_sec:n,usb:{tx_ok:n,ncm:{ntb_completed:n},tx_queue:{full:0}}});
  const samples=[{time:iso(8),finished:iso(8.1),status:state(100)},
    {time:iso(9),finished:iso(12),error:'API timeout'},
    {time:iso(12),finished:iso(12.1),status:state(104)}];
  const [b]=blackoutDiagnostics([record],pings,samples);
  assert.equal(b.board.replies,1);assert.equal(b.board.timeouts,0);assert.equal(b.server.timeouts,1);
  assert.equal(b.telemetry.api_errors.length,1);assert.equal(b.telemetry.counters['usb.tx_ok'],4);
  assert.match(reportMarkdown({blackouts:[b]}),/4 \/ 4 \/ 0/);
  samples[2].status=state(1);
  assert.equal(blackoutDiagnostics([record],pings,samples)[0].telemetry.counters['usb.tx_ok'],null);
  samples[2].time=iso(30);samples[2].finished=iso(30.1);
  assert.equal(blackoutDiagnostics([record],pings,samples)[0].telemetry.counters,null);
  assert.equal(blackoutDiagnostics([record],[],[])[0].board,null);
  record.timing.receiver_interval_source='server';
  assert.equal(blackoutDiagnostics([record],pings,samples)[0].alignment,'unknown');
  record.timing.receiver_interval_source='client';record.timing.client_timestamp_ms=null;
  assert.equal(blackoutDiagnostics([record],pings,samples)[0].telemetry,null);
});

test('subprocess timestamps complete lines across chunks and retains final unterminated line',async()=>{
  const observed=[];
  await command(process.execPath,['-e','process.stdout.write("first\\nsec");setTimeout(()=>process.stdout.write("ond"),10)'],
    {onStdoutLine:(line,ms)=>observed.push({line,ms})});
  assert.deepEqual(observed.map(x=>x.line),['first','second']);
  assert.ok(observed.every(x=>Number.isFinite(x.ms)));
});

// Reduced from the user's 0008 report: last three intervals and unmodified end statistics.
const tailStall=JSON.parse(await readFile(new URL('./fixtures/iperf-udp-tail-stall.json',import.meta.url),'utf8'));
test('tail receive blackout and unequal durations warn without rewriting measurements',()=>{
  const r=parseIperf(JSON.stringify(tailStall),'udp'),d=r.timing;
  assert.equal(r.mbps,tailStall.end.sum_received.bits_per_second/1e6);assert.equal(r.lost_percent,0.34984764699243875);
  assert.equal(d.sender_seconds,17.012893);assert.equal(d.receiver_seconds,15.005008);
  assert.ok(Math.abs(d.duration_delta_seconds-2.007885)<1e-9);
  assert.deepEqual(d.warnings,['duration_mismatch','zero_receive_interval']);
  assert.equal(d.zero_receive_intervals[0].start,14.005003);assert.equal(d.receiver_interval_source,'client');
  assert.equal(d.client_version,'iperf 3.21');assert.equal(d.server_version,'iperf 3.9');
  const record={...r,id:'0008',path:'usb',phase:'single',protocol:'udp',direction:'down',warmup:false};
  assert.equal(summarize([record])['single/usb/udp/down/'].mbps.median,r.mbps);
  assert.match(reportMarkdown({records:[record]}),/14.01–15.01/);
});

test('timing diagnostics ignore omitted/tiny/sender intervals and retain missing data as unknown',()=>{
  const j=structuredClone(tailStall);
  j.start.timestamp={timesecs:1789246166,timemillisecs:1789246166176};
  assert.equal(parseIperf(JSON.stringify(j),'udp').timing.client_timestamp_ms,1789246166176);
  delete j.start.timestamp.timemillisecs;
  assert.equal(parseIperf(JSON.stringify(j),'udp').timing.client_timestamp_ms,1789246166000);
  j.end.sum_sent.seconds=15.005008;
  j.intervals=[{sum:{start:0,end:1,seconds:1,bytes:0,sender:false,omitted:true}},
    {sum:{start:1,end:2,seconds:1,bytes:0,sender:true}},
    {sum:{start:2,end:3,seconds:1,sender:false}},
    {sum:{start:3,end:3.1,seconds:0.1,bytes:0,sender:false}}];
  let d=parseIperf(JSON.stringify(j),'udp').timing;
  assert.deepEqual(d.warnings,[]);assert.equal(d.zero_receive_intervals.length,1);
  delete j.intervals;delete j.end.sum_sent.seconds;delete j.end.sum_received.seconds;
  d=parseIperf(JSON.stringify(j),'udp').timing;
  assert.equal(d.receiver_interval_count,null);assert.equal(d.zero_receive_intervals,null);
  assert.equal(d.duration_delta_seconds,null);assert.deepEqual(d.warnings,[]);
  // Upload: client sender stalls must not be labelled as receiver intervals.
  j.start.test_start.reverse=0;
  j.intervals=[{sum:{start:0,end:1,seconds:1,bytes:0,sender:true}}];
  j.server_output_json.intervals=[{sum:{start:0,end:1,seconds:1,bytes:0,sender:false}}];
  d=parseIperf(JSON.stringify(j),'udp').timing;
  assert.equal(d.receiver_interval_source,'server');assert.deepEqual(d.warnings,['zero_receive_interval']);
  // A shorter sender window also needs a warning; small timing drift does not.
  j.end.sum_sent.seconds=14;j.end.sum_received.seconds=15;
  assert.ok(parseIperf(JSON.stringify(j),'udp').timing.warnings.includes('duration_mismatch'));
  j.end.sum_sent.seconds=15.2;
  assert.ok(!parseIperf(JSON.stringify(j),'udp').timing.warnings.includes('duration_mismatch'));
});

test('ping packet loss warrants warning even without a command error', () => {
  assert.equal(hasPingProblem([]),false);
  assert.equal(hasPingProblem([{loss_percent:0},{loss_percent:null}]),false);
  assert.equal(hasPingProblem([{loss_percent:0},{loss_percent:0.01}]),true);
  assert.equal(hasPingProblem([{loss_percent:100}]),true);
  assert.equal(hasPingProblem([{error:'timeout'}]),true);
});

const paths=[{kind:'usb',iface:'en7',address:'192.168.7.2',gateway:'192.168.7.1'},
  {kind:'ap',iface:'en0',address:'192.168.4.2',gateway:'192.168.4.1'}];
const interfaces=()=>Object.fromEntries(paths.map(p=>[p.iface,[{family:'IPv4',address:p.address,netmask:'255.255.255.0',internal:false}]]));
const fixture=()=>({uptime_sec:100,build:'test-build',wifi:{connected:true,rssi:-50,scanning:false},
  net:{usb_ip:paths[0].gateway,ap_ip:paths[1].gateway,usb_napt:true,ap_napt:true,ap_active:true,ap_ip4_rx:500,lan_ip4_rx:1000},
  usb:{host_ready:true,tx_ok:100,tx_dropped:3,tx_retried:4},temperature_c:42,
  memory:Object.fromEntries(['internal','dma','psram'].map(k=>[k,{free:200000,largest_block:100000,minimum_free:180000}])),
  cpu:{available:true,sampled_us:1000000,sample_age_ms:10,collection_us:100,cores:[{id:0,load_pct:20},{id:1,load_pct:.5}],tasks:[]}});
const iperfJSON=(address,udp=false)=>JSON.stringify({start:{connected:[{local_host:address}]},
  end:{sum_received:{bits_per_second:8e6,...(udp?{lost_percent:1,jitter_ms:2}:{})},sum_sent:{bits_per_second:9e6,...(udp?{}:{retransmits:4})}}});
const pingText='64 bytes from 1.2.3.4: icmp_seq=0 ttl=63 time=1.0 ms\n64 bytes from 1.2.3.4: icmp_seq=1 ttl=63 time=3.0 ms\n2 packets transmitted, 2 packets received, 0.0% packet loss\n';

test('CLI: SSH/data ports, defaults, quick overrides and injection rejection',()=>{
  const o=parseArgs(['alice@192.168.1.10:2222','--quick','--seconds','7']);
  assert.equal(o.sshTarget,'alice@192.168.1.10');assert.equal(o.sshPort,2222);assert.equal(o.iperfPort,5201);
  assert.equal(o.soakMinutes,0);assert.equal(o.runs,2);assert.equal(o.seconds,7);
  assert.equal(parseArgs(['--help']).help,true);
  assert.equal(parseArgs(['host','--usb-down-sweep','--start-delay','60']).startDelay,60);
  assert.equal(parseArgs(['host']).startDelay,0);
  for(const value of ['-1','601','NaN','1.5'])assert.throws(()=>parseArgs(['host','--start-delay',value]));
  for(const args of [[],['-oProxyCommand=bad'],['user@host;id'],['host:0'],['host','--iperf-port','65535'],
    ['host','--seconds','NaN'],['host','--runs'],['host','--server-ip','::1'],['host','--paths','xxx'],['host','--install']])
    assert.throws(()=>parseArgs(args));
  const ssh=sshArgs(o);assert.ok(ssh.includes('BatchMode=yes'));assert.ok(ssh.includes('StrictHostKeyChecking=yes'));
  assert.ok(!ssh.includes('-L'));assert.ok(!ssh.includes('-R'));
});

test('shell quoting and subprocess timeout/cancellation preserve diagnostics',async()=>{
  const value="a'b; $(echo no)";
  assert.equal((await command('sh',['-c',`printf %s ${quote(value)}`])).stdout,value);
  const r=await command(process.execPath,['-e','process.stderr.write("failure");process.exit(7)']);
  assert.equal(r.code,7);assert.equal(r.stderr,'failure');
  await assert.rejects(command(process.execPath,['-e','setInterval(()=>{},100)'],{timeout:50}),/timeout/);
  const c=new AbortController();c.abort();
  await assert.rejects(command(process.execPath,['-e','setInterval(()=>{},100)'],{signal:c.signal}),/Interrupted/);
  await assert.rejects(command('/nonexistent-meshpn-test',[]),/ENOENT/);
});

test('USB sweep preset is order independent and rejects conflicting suites',()=>{
  for(const args of [['--usb-down-sweep','host'],['host','--usb-down-sweep']]) {
    const o=parseArgs(args);
    assert.equal(o.paths,'usb');assert.equal(o.seconds,15);assert.equal(o.runs,3);
    assert.equal(o.soakMinutes,0);assert.equal(o.idleSeconds,10);
  }
  for(const extra of [['--quick'],['--paths','ap'],['--paths','both'],['--seconds','3'],['--runs','2'],['--soak-minutes','1']])
    for(const args of [['host','--usb-down-sweep',...extra],['host',...extra,'--usb-down-sweep']])assert.throws(()=>parseArgs(args),/requires USB only/);
  assert.equal(parseArgs(['--usb-down-sweep','--help']).help,true);
});

test('USB sweep runs 18 measured UDP downloads, six warmups, recovery gaps and no other load',async()=>{
  const o=parseArgs(['host','--usb-down-sweep']),batches=[],idles=[];
  assert.throws(()=>measurementPlan(paths,o),/exactly one USB/);
  assert.throws(()=>measurementPlan([paths[1]],o),/exactly one USB/);
  await executeSchedule(o,[paths[0]],{batch:async t=>batches.push(t),idle:async(name,seconds)=>idles.push({name,seconds})});
  assert.equal(batches.length,24);assert.equal(batches.filter(t=>!t.warmup).length,18);
  assert.ok(batches.every(t=>t.paths.length===1&&t.paths[0].kind==='usb'&&t.direction==='down'&&t.protocol==='udp'));
  for(const rate of [5,6,7,8,9,10]) {
    const group=batches.filter(t=>t.rate===rate);
    assert.deepEqual(group.map(t=>t.run),[0,1,2,3]);
    assert.deepEqual(group.map(t=>t.seconds),[3,15,15,15]);
  }
  assert.equal(idles[0].name,'baseline-idle');assert.equal(idles.at(-1).name,'final-idle');
  assert.equal(idles.filter(i=>i.name.startsWith('sweep-recovery-')&&i.seconds===3).length,23);
  assert.equal(batches.reduce((s,t)=>s+t.seconds,0)+idles.reduce((s,t)=>s+t.seconds,0),377);
});

test('USB sweep summary excludes warmups, matches ping by ID/path, and preserves unknown counters',()=>{
  const counters=Object.fromEntries(usbQueueCounterFields.map(k=>[`usb.tx_queue.${k}`,0]));
  Object.assign(counters,{'usb.tx_queue.submitted':100,'usb.tx_queue.full':5,'usb.tx_queue.send_failed':2,
    'usb.tx_queue.completed':90,'usb.tx_queue.residence_us':180000,'usb.tx_dropped':2});
  const base={id:'1',phase:'usb-down-sweep',path:'usb',protocol:'udp',direction:'down',rate:5,warmup:false,
    mbps:4,sender_mbps:4.9,lost_percent:1,batch_counters:counters};
  const records=[base,{...base,id:'2',mbps:5,lost_percent:3},{...base,id:'warm',warmup:true,mbps:1000},
    {...base,id:'fail',error:'failed'},{...base,path:'ap',mbps:900}];
  const pings=[{id:'1',path:'usb',rtt_ms:{p95:10},loss_percent:0},{id:'2',path:'usb',rtt_ms:{p95:30},loss_percent:4},
    {id:'warm',path:'usb',rtt_ms:{p95:1000}},{id:'1',path:'ap',rtt_ms:{p95:1000}},
    {id:'1',path:'usb',target:'board',rtt_ms:{p95:1000},loss_percent:100}];
  let row=summarizeUsbDownSweep(records,pings)[0];
  assert.equal(row.n,2);assert.equal(row.failed,1);assert.equal(row.receiver_mbps.median,4.5);
  assert.equal(row.queue_losses,14);assert.equal(row.full,10);assert.equal(row.queue_loss_percent,7);
  assert.equal(row.residence_mean_ms,2);assert.equal(row.ping_p95_ms.median,20);assert.equal(row.ping_loss.max,4);
  assert.equal(row.udp_loss.median,2);assert.equal(row.udp_loss.max,3);
  const report=reportMarkdown({options:{usbDownSweep:true},records,pings});
  assert.match(report,/USB download rate sweep/);assert.match(report,/14 \/ 7.00/);
  row=summarizeUsbDownSweep([base,{...base,batch_counters:{}}])[0];
  assert.equal(row.queue_losses,null);assert.equal(row.queue_loss_percent,null);assert.equal(row.full,null);
  assert.equal(summarizeUsbDownSweep([])[0].receiver_mbps,null);
  assert.match(reportMarkdown({options:{usbDownSweep:true}}),/n\/a/);
});

test('interface binding, direction and UDP packet size are explicit',()=>{
  const args=iperfArgs('1.2.3.4',5202,paths[1],{seconds:30,protocol:'udp',direction:'down',rate:10});
  for(const flag of ['-4','-R','--get-server-output','-J','-B'])assert.ok(args.includes(flag));
  assert.ok(!args.includes('--bind-dev'));assert.equal(args[args.indexOf('-B')+1],paths[1].address);
  assert.equal(args[args.indexOf('-l')+1],'1200');assert.equal(args[args.indexOf('-b')+1],'10M');
});

test('macOS helper build, process-only environment and binding evidence fail closed',async()=>{
  const calls=[],sdk='/toolchain/SDK with spaces/MacOSX.sdk';
  const library=await prepareIperfBinding('/tmp/results with spaces',undefined,{run:async(bin,args,opts)=>{
    calls.push({bin,args,opts});return calls.length===1?'/toolchain/clang\n':calls.length===2?sdk+'\n':'';
  },checkAccess:async file=>{assert.equal(file,sdk+'/usr/include/sys/socket.h');}});
  assert.equal(calls[0].bin,'/usr/bin/xcrun');assert.equal(calls[2].bin,'/toolchain/clang');
  assert.deepEqual(calls[0].args,['--sdk','macosx','--find','clang']);
  assert.deepEqual(calls[1].args,['--sdk','macosx','--show-sdk-path']);
  assert.equal(calls[0].opts.env.SDKROOT,undefined);assert.equal(calls[1].opts.env.SDKROOT,undefined);
  assert.equal(calls[2].opts.env.SDKROOT,sdk);
  assert.deepEqual(calls[2].args.slice(0,2),['-isysroot',sdk]);
  assert.ok(calls[2].args.includes('-dynamiclib'));assert.ok(calls[2].args.includes('arm64'));
  assert.ok(calls[2].args.includes('x86_64'));assert.equal(calls[2].args.at(-1),library);
  const original=process.env.DYLD_INSERT_LIBRARIES;
  assert.equal(iperfEnvironment(library,'en13').DYLD_INSERT_LIBRARIES,library);
  assert.equal(iperfEnvironment(library,'en0').MESHPN_IPERF_IFACE,'en0');
  assert.equal(process.env.DYLD_INSERT_LIBRARIES,original);
  assert.throws(()=>iperfEnvironment(library,'bad\niface'));
  verifyIperfBinding('MESHPN_BOUND_IF=en13\n','en13');
  assert.throws(()=>verifyIperfBinding('MESHPN_BOUND_IF=en0\n','en13'),/unverified/);
  assert.throws(()=>verifyIperfBinding('','en13'),/unverified/);
  assert.equal(iperfError({stdout:'{"error":"connection refused"}',stderr:'MESHPN_BOUND_IF=en13\n'}),'connection refused');
  await assert.rejects(prepareIperfBinding('/tmp/with:colon'),/colon/);
  await assert.rejects(prepareIperfBinding('/tmp/results',undefined,{run:async()=>{throw Error('missing');}}),/xcode-select --install/);
});

test('missing or incomplete macOS SDK fails before compiling; cancellation is preserved',async()=>{
  for(const sdk of ['', 'relative/path', '/missing/MacOSX.sdk']) {
    let calls=0;
    await assert.rejects(prepareIperfBinding('/tmp/results',undefined,{
      run:async()=>{calls++;return calls===1?'/toolchain/clang':sdk;},
      checkAccess:async()=>{throw Error('ENOENT: sys/socket.h');}
    }),/SDK unavailable\/incomplete/);
    assert.equal(calls,2);
  }
  const controller=new AbortController();controller.abort();
  await assert.rejects(macosBuildContext(controller.signal,{run:async()=>{throw Error('Interrupted');}}),/^Error: Interrupted$/);
});

test('native macOS dyld binds both TCP and UDP sockets without sending traffic',
  {skip:process.platform!=='darwin'},async()=>{
    const dir=await mkdtemp(path.join(tmpdir(),'meshpn-native-bind-'));
    try {
      const library=await prepareIperfBinding(dir);
      const probe=path.join(dir,'probe');
      const {compiler,sdk,env:buildEnv}=await macosBuildContext();
      const built=await command(compiler,['-isysroot',sdk,'-Wall','-Wextra','-Werror',
        fileURLToPath(new URL('./perf_bind_darwin_probe.c',import.meta.url)),'-o',probe],{env:buildEnv});
      assert.equal(built.code,0,built.stderr);
      const env={...process.env,DYLD_INSERT_LIBRARIES:library,MESHPN_IPERF_IFACE:'lo0'};
      const raw=await command(probe,[],{env});
      assert.equal(raw.code,0,raw.stderr);verifyIperfBinding(raw.stderr,'lo0');
    }finally{await rm(dir,{recursive:true,force:true});}
});

test('throughput uses receiver, old UDP server JSON fallback, missing data is not zero',()=>{
  assert.equal(parseIperf(iperfJSON(paths[0].address),'tcp').mbps,8);
  assert.equal(parseIperf(iperfJSON(paths[0].address,true),'udp').lost_percent,1);
  const old={end:{sum:{bits_per_second:10e6,sender:true}},server_output_json:{end:{sum:{bits_per_second:7e6,sender:false,lost_percent:30,jitter_ms:3}}}};
  assert.equal(parseIperf(JSON.stringify(old),'udp').mbps,7);
  assert.throws(()=>parseIperf('{"error":"server busy"}','tcp'),/server busy/);
  assert.throws(()=>parseIperf('{"end":{"sum_sent":{"bits_per_second":100}}}','tcp'),/receiver/);
  assert.throws(()=>parseIperf('not json','tcp'));
  assert.equal(stats([undefined,null,NaN]),null);
  assert.deepEqual(stats([3,1,2]),{count:3,min:1,median:2,p95:2.9,max:3});
  assert.equal(parsePing(pingText).rtt_ms.median,2);assert.equal(parsePing(pingText).loss_percent,0);
  assert.equal(parsePing('timeout').rtt_ms,null);assert.equal(parsePing('timeout').loss_percent,null);
});

test('plan has five repeats plus warm-up, both directions and simultaneous separate paths',()=>{
  const o=parseArgs(['host']),plan=measurementPlan(paths,o);
  assert.equal(plan.length,84);assert.equal(plan.filter(p=>p.warmup).length,14);
  assert.equal(plan.filter(p=>p.phase==='combined').length,12);
  assert.ok(plan.filter(p=>p.phase==='combined').every(p=>p.paths.length===2&&p.protocol==='tcp'));
  assert.equal(measurementPlan([paths[0]],o).length,36);
  const r={phase:'single',path:'usb',protocol:'tcp',direction:'up',mbps:8};
  const summary=summarize([{...r,warmup:true,mbps:1000},r,{...r,error:'failure'}]);
  assert.equal(summary['single/usb/tcp/up/'].mbps.median,8);assert.equal(summary['single/usb/tcp/up/'].failed,1);
});

test('entire schedule including 30-minute soak executes with fake time',async()=>{
  const o=parseArgs(['host']),batches=[],idles=[];let now=0;
  await executeSchedule(o,paths,{now:()=>now,batch:async t=>{batches.push(t);now+=t.seconds*1000;},
    idle:async(name,seconds)=>{idles.push({name,seconds});now+=seconds*1000;}});
  assert.deepEqual(idles.map(x=>x.name),['baseline-idle','soak-1-idle','soak-2-idle','final-idle']);
  assert.equal(idles[1].seconds,300);assert.equal(idles[2].seconds,300);
  assert.equal(batches.filter(b=>b.phase==='soak-1').length,10);
  assert.equal(batches.filter(b=>b.phase==='soak-2').length,10);
});

test('counter resets, CPU deduplication, unavailable telemetry and sanitized output',()=>{
  const before=fixture(),after=fixture();after.usb.tx_dropped+=2;
  assert.equal(counterDelta(before,after)['usb.tx_dropped'],2);
  after.uptime_sec=1;assert.equal(counterDelta(before,after)['usb.tx_dropped'],null);
  after.uptime_sec=100;after.usb.tx_dropped=0;assert.equal(counterDelta(before,after)['usb.tx_dropped'],null);
  before.token='SECRET';before.vpn={password:'SECRET'};before.wifi.password='SECRET';
  assert.ok(!JSON.stringify(cleanStatus(before)).includes('SECRET'));
  const samples=[0,1].map(i=>({time:String(i),elapsed_ms:i*2000,phase:'baseline-idle',status:cleanStatus(before)}));
  samples.push({time:'2',error:'timeout'});
  const t=telemetrySummary(samples);assert.equal(t.cpu_samples,1);assert.equal(t.api_errors,1);assert.equal(t.cpu_load[0].median,20);
  assert.equal(telemetrySummary([]).cpu_load[0],null);
  samples.push({time:'3',elapsed_ms:6000,phase:'final-idle',status:cleanStatus({...before,uptime_sec:1})});
  assert.equal(telemetrySummary(samples).events.length,1);assert.equal(telemetrySummary(samples).cpu_samples,2);
  samples.push({time:'4',elapsed_ms:600000,phase:'final-idle',status:cleanStatus({...before,uptime_sec:500})});
  assert.equal(telemetrySummary(samples).counter_delta['usb.tx_dropped'],null);
});

test('USB TX telemetry survives sanitization, reports per-batch deltas and keeps missing data unknown',()=>{
  const before=fixture(),after=fixture();
  const values={tx_timeout:2,tx_calls:8,tx_attempts:10,tx_busy:4,tx_busy_exhausted:1,
    tx_no_mem:1,tx_invalid_state:0,tx_other_error:0,tx_wait_us:16000,tx_wait_le_1ms:4,
    tx_wait_1_5ms:2,tx_wait_5_25ms:1,tx_wait_gt_25ms:1};
  for(const [k,v] of Object.entries(values)){before.usb[k]=100;after.usb[k]=100+v;}
  after.usb.tx_wait_max_us=100000;after.usb.tx_attempts_max=64;
  const clean=cleanStatus(after),delta=counterDelta(cleanStatus(before),clean);
  for(const [k,v] of Object.entries(values))assert.equal(delta[`usb.${k}`],v);
  assert.equal(clean.usb.tx_wait_max_us,100000);assert.equal(clean.usb.tx_attempts_max,64);
  assert.equal(delta['usb.tx_wait_max_us'],undefined);
  assert.equal(counterDelta(fixture(),fixture())['usb.tx_timeout'],null);
  const record={id:'0001',phase:'combined',protocol:'tcp',direction:'down',batch_counters:delta};
  const report=reportMarkdown({records:[{...record,path:'usb'},{...record,path:'ap'}]});
  assert.equal(report.split('| 0001 |').length-1,1);
  assert.ok(report.includes('combined/usb+ap/tcp/down'));
  assert.ok(report.includes('| 2.00 | 1 |'));
  assert.ok(reportMarkdown({records:[{...record,path:'usb',batch_counters:{}}]}).includes('| n/a |'));
  after.uptime_sec=0;
  assert.equal(counterDelta(before,after)['usb.tx_wait_us'],null);
});

test('NCM nested telemetry, batch means and unavailable/reset counters are preserved honestly',()=>{
  const before=fixture(),after=fixture();
  before.usb.ncm={available:true,...Object.fromEntries(ncmCounterFields.map(k=>[k,0]))};
  after.usb.ncm={...before.usb.ncm,ntb_started:2,bytes_started:4000,frames_started:6,
    completion_timed:2,completion_us:6000,backlog_gaps:1,backlog_gap_us:1000,busy_no_free:3,
    pool:6,free_min:0,ready_max:5,max_ntb:8192,max_datagrams:6,completion_max_us:5000,secret:'HIDDEN'};
  const clean=cleanStatus(after),delta=counterDelta(cleanStatus(before),clean);
  assert.equal(delta['usb.ncm.ntb_started'],2);
  assert.equal(delta['usb.ncm.completion_us'],6000);
  assert.equal(delta['usb.ncm.completion_max_us'],undefined);
  assert.equal(clean.usb.ncm.free_min,0);
  assert.ok(!JSON.stringify(clean).includes('HIDDEN'));
  const record={id:'0007',phase:'combined',protocol:'tcp',direction:'down',batch_counters:delta};
  const report=reportMarkdown({records:[{...record,path:'usb'},{...record,path:'ap'}]});
  assert.ok(report.includes('NCM transfers by batch'));
  assert.equal(report.split('| 0007 | 2 | 2000.00 | 3.00 | 3 | 3.00 | 1.00 | 0 / 0 |').length-1,1);
  assert.equal(counterDelta(fixture(),after)['usb.ncm.ntb_started'],null);
  after.uptime_sec=0;
  assert.equal(counterDelta(before,after)['usb.ncm.ntb_started'],null);
  assert.ok(!reportMarkdown({records:[{...record,batch_counters:{}}]}).includes('NCM transfers by batch'));
});

test('USB worker queue counters, ownership loss stages and batch means survive reporting',()=>{
  const before=fixture(),after=fixture();
  before.usb.tx_queue={enabled:true,...Object.fromEntries(usbQueueCounterFields.map(k=>[k,0]))};
  after.usb.tx_mode='queued';
  after.usb.tx_queue={...before.usb.tx_queue,submitted:10,enqueued:8,completed:8,sent:5,full:2,
    expired:1,stale:1,send_failed:1,queue_wait_us:16000,residence_us:24000,high_water:8,secret:'HIDDEN',
    event_wait:true,capacity_waits:4,capacity_wakeups:3,capacity_timeouts:1,capacity_wait_us:12000};
  const clean=cleanStatus(after),delta=counterDelta(cleanStatus(before),clean);
  assert.equal(clean.usb.tx_mode,'queued');
  assert.ok(!JSON.stringify(clean).includes('HIDDEN'));
  assert.equal(delta['usb.tx_queue.full'],2);
  assert.equal(delta['usb.tx_queue.residence_us'],24000);
  assert.equal(delta['usb.tx_queue.capacity_waits'],4);
  assert.equal(delta['usb.tx_queue.capacity_timeouts'],1);
  assert.equal(clean.usb.tx_queue.event_wait,true);
  assert.equal(delta['usb.tx_queue.high_water'],undefined);
  const r={id:'0009',phase:'combined',protocol:'tcp',direction:'down',batch_counters:delta};
  const report=reportMarkdown({records:[{...r,path:'usb'},{...r,path:'ap'}]});
  assert.equal(report.split('| 0009 | 8 | 5 | 2 | 1 | 1 | 1 | 2.00 | 3.00 | 4 | 1 | 3.00 |').length-1,1);
  assert.equal(counterDelta(fixture(),after)['usb.tx_queue.full'],null);
  const samples=[before,after].map(status=>({status:cleanStatus(status)}));
  const summary=telemetrySummary(samples);
  assert.ok(summary.usb_queue_last.enabled);
  assert.ok(reportMarkdown({telemetry:summary}).includes('do not add twice'));
  after.uptime_sec=1;
  assert.equal(counterDelta(before,after)['usb.tx_queue.full'],null);
  summary.usb_queue_last={enabled:false,init_failed:1};
  assert.ok(reportMarkdown({telemetry:summary}).includes('synchronous fallback'));
});

test('route parser and validator fail closed on bypass, missing gateway and vanished address',async()=>{
  assert.deepEqual(macRoute('   gateway: 192.168.7.1\n interface: en7\n'),{gateway:'192.168.7.1',iface:'en7'});
  assert.equal(sameSubnet('192.168.7.2','192.168.7.1','255.255.255.0'),true);
  assert.equal(sameSubnet('192.168.7.2','192.168.4.1','255.255.255.0'),false);
  assert.equal(sameSubnet('192.168.7.2','bad','255.255.255.0'),false);
  const deps={networkInterfaces:interfaces,run:async()=> 'gateway: 192.168.7.1\ninterface: en7\n'};
  await checkRoute(paths[0],'1.2.3.4',undefined,deps);
  await assert.rejects(checkRoute(paths[0],'1.2.3.4',undefined,{...deps,run:async()=> 'gateway: 192.168.1.1\ninterface: en0\n'}),/bypass/);
  await assert.rejects(checkRoute(paths[0],'1.2.3.4',undefined,{...deps,networkInterfaces:()=>({})}),/disconnected/);
});

test('discover DHCP paths once, reuse a single login and do not invoke Wi-Fi scan',async()=>{
  let logins=0;const requests=[];
  const board=await discoverBoard({paths:'both'},new AbortController().signal,()=>{},
    {networkInterfaces:interfaces,run:async(bin,args)=>({code:0,stdout:paths.find(p=>p.iface===args[1]).gateway}),
      request:async(c,url,auth)=>{
        requests.push(url);
        if(url==='/login')return {code:200,text:'<title>MeshPN Login</title>'};
        if(url==='/api/login'){logins++;return {code:200,text:'{"token":"test-token"}'};}
        assert.equal(auth.token,'test-token');return {code:200,text:JSON.stringify(fixture())};
      }});
  assert.deepEqual(board.paths.map(p=>p.kind),['usb','ap']);await board.status();assert.equal(logins,1);
  assert.ok(!requests.some(p=>p.includes('scan')));
});

test('discovery will not send passwords to routers or arbitrary HTTPS redirects',async()=>{
  let posted=false;
  await assert.rejects(discoverBoard({paths:'auto'},new AbortController().signal,()=>{},
    {networkInterfaces:interfaces,run:async(bin,args)=>({code:0,stdout:paths.find(p=>p.iface===args[1]).gateway}),
      request:async(c,url)=>{
        if(url==='/api/login')posted=true;
        return c.iface==='en7'?{code:200,text:'<title>Router</title>'}:{code:302,location:'https://unexpected.example/',text:''};
      }}),/not found/);
  assert.equal(posted,false);
});

test('missing AP reports expected network, preserves board identity and distinguishes timeout',async()=>{
  for(const timeout of [false,true]) {
    const initial=fixture();initial.net.ap_ssid='MeshPN_test';
    const deps={networkInterfaces:interfaces,
      run:async(bin,args)=>({code:0,stdout:paths.find(p=>p.iface===args[1]).gateway}),
      request:async(c,url)=>{
        if(c.iface==='en0') {
          if(timeout)throw Error('Board API timeout');
          return {code:200,text:'<title>Router</title>'};
        }
        if(url==='/login')return {code:200,text:'<title>MeshPN Login</title>'};
        if(url==='/api/login')return {code:200,text:'{"token":"test-token"}'};
        return {code:200,text:JSON.stringify(initial)};
      }};
    await assert.rejects(discoverBoard({paths:'both'},new AbortController().signal,()=>{},deps),e=>{
      assert.match(e.message,/found: usb/);assert.match(e.message,/MeshPN_test/);
      assert.match(e.message,/--paths usb/);assert.match(e.message,/en0.*192\.168\.4\.1/);
      assert.match(e.message,timeout?/Board API timeout/:/not a MeshPN login page/);
      assert.equal(e.boardInitial.build,'test-build');
      assert.deepEqual(e.discovery.detectedPaths.map(p=>p.kind),['usb']);
      assert.ok(!JSON.stringify(e.discovery).includes('test-token'));
      return true;
    });
    const board=await discoverBoard({paths:'usb'},new AbortController().signal,()=>{},deps);
    assert.deepEqual(board.paths.map(p=>p.kind),['usb']);
  }
});

test('HTTP API sends credentials only as body, handles HTTP errors and binds source',async()=>{
  let seen;
  const server=http.createServer(async(req,res)=>{
    let body='';for await(const b of req)body+=b;
    seen={url:req.url,authorization:req.headers.authorization,body,source:req.socket.remoteAddress};
    res.writeHead(401,{'Content-Type':'application/json'});res.end('{"error":"invalid"}');
  });
  server.listen(0,'127.0.0.1');await once(server,'listening');
  try {
    const r=await requestBoard({gateway:'127.0.0.1',address:'127.0.0.1',port:server.address().port,protocol:'http:'},'/api/login',{password:'test-secret'});
    assert.equal(r.code,401);assert.equal(seen.body,'{"password":"test-secret"}');assert.equal(seen.authorization,undefined);
    assert.equal(seen.url,'/api/login');assert.equal(seen.source,'127.0.0.1');
  }finally{server.close();}
});

test('remote supervisor reaps servers on EOF/heartbeat loss and preserves an occupied port',{timeout:15000},async()=>{
  const dir=await mkdtemp(path.join(tmpdir(),'meshpn-perf-remote-'));
  const executable=path.join(dir,'iperf3');let child;
  const occupied=net.createServer();occupied.listen(0,'127.0.0.1');await once(occupied,'listening');
  try {
    await writeFile(executable,`#!/usr/bin/env node
const net=require('net'),fs=require('fs');
const port=Number(process.argv[process.argv.indexOf('-p')+1]);
fs.writeFileSync(process.env.TEST_PID_DIRECTORY+'/'+port+'.pid',String(process.pid));
net.createServer().listen(port,'127.0.0.1');
`,{mode:0o700});
    const env={...process.env,PATH:dir+path.delimiter+process.env.PATH,TEST_PID_DIRECTORY:dir};
    const launch=(ports,program=remoteServer)=>{
      const p=spawn('python3',['-u','-c',program,...ports.map(String)],{env,stdio:['pipe','pipe','pipe']});
      let stdout='',stderr='';p.stdout.on('data',b=>{stdout+=b;});p.stderr.on('data',b=>{stderr+=b;});
      return {p,output:()=>stdout,closed:once(p,'close'),stderr:()=>stderr};
    };
    // Port 0 is sufficient for supervisor lifecycle tests (the OS chooses the actual port).
    child=launch([0]);
    for(let i=0;i<100&&!child.output().includes('MESHPN_READY');i++)await delay(30);
    assert.match(child.output(),/MESHPN_READY/);
    const pid=Number(await readFile(path.join(dir,'0.pid'),'utf8'));
    child.p.stdin.end();assert.equal((await child.closed)[0],0);
    assert.throws(()=>process.kill(pid,0),/ESRCH/);
    child=launch([0,occupied.address().port]);
    assert.notEqual((await child.closed)[0],0);assert.ok(occupied.listening);
    const otherPid=Number(await readFile(path.join(dir,'0.pid'),'utf8'));
    assert.throws(()=>process.kill(otherPid,0),/ESRCH/);
    child=launch([0],remoteServer.replace('lease_seconds = 30','lease_seconds = 1'));
    for(let i=0;i<100&&!child.output().includes('MESHPN_READY');i++)await delay(30);
    assert.match(child.output(),/MESHPN_READY/);
    for(let i=0;i<4;i++){child.p.stdin.write('heartbeat\n');await delay(500);}
    assert.equal(child.p.exitCode,null);
    assert.equal((await child.closed)[0],0); // No EOF: a lost heartbeat alone must reap children.
    const leasePid=Number(await readFile(path.join(dir,'0.pid'),'utf8'));
    assert.throws(()=>process.kill(leasePid,0),/ESRCH/);
  }finally{child?.p.stdin.end();occupied.close();await rm(dir,{recursive:true,force:true});}
});

test('runner integration: full quick suite, files, two ports, cleanup and failure report',async()=>{
  const parent=await mkdtemp(path.join(tmpdir(),'meshpn-perf-runner-'));let closes=0,fail=false;
  const portsSeen=new Set(),signalsBefore=process.listenerCount('SIGINT');
  let ticks=0;const delays=[],pingTargets=new Set();
  const dependencies={platform:'darwin',log:()=>{},lookup:async()=>({address:'1.2.3.4'}),delay:async(ms)=>{delays.push(ms);},
    prepareIperfBinding:async()=>'/tmp/test-bind.dylib',
    checked:async(bin)=>bin==='iperf3'?'iperf3 test':'test',
    discoverBoard:async()=>({paths,initial:fixture(),status:async()=>{const f=fixture();f.uptime_sec+=ticks++;f.cpu.sampled_us+=ticks*2000000;return f;}}),
    checkRoute:async()=> 'validated test route',spawn:()=>({on(){},kill(){}}),
    startServers:async()=>({ports:[5201,5202],assertAlive(){},async close(){closes++;}}),
    command:async(bin,args,opts)=>{
      if(bin==='ssh')return {code:0,stdout:'iperf3 test\nPython 3 test',stderr:''};
      if(bin==='/sbin/ping'){
        pingTargets.add(args.at(-1));
        assert.ok(args.includes('-b'));assert.ok(args.includes('-S'));
        for(const line of pingText.trim().split('\n'))opts.onStdoutLine?.(line,Date.now());
        return {code:0,stdout:pingText,stderr:''};
      }
      assert.equal(bin,'iperf3');portsSeen.add(args[args.indexOf('-p')+1]);
      if(fail==='interrupt'){process.emit('SIGINT');throw Error('Interrupted');}
      return fail?{code:1,stdout:'{"error":"test server busy"}',stderr:''}:
        {code:0,stdout:iperfJSON(args[args.indexOf('-B')+1],args.includes('-u')),
          stderr:`MESHPN_BOUND_IF=${paths.find(p=>p.address===args[args.indexOf('-B')+1]).iface}\n`};
    }};
  try {
    assert.equal(await main(['user@server:2222','--quick','--start-delay','60','--out',parent],dependencies),0);
    assert.equal(closes,1);assert.deepEqual([...portsSeen].sort(),['5201','5202']);
    let dirs=await readdir(parent);const dir=path.join(parent,dirs[0]);
    const result=JSON.parse(await readFile(path.join(dir,'result.json'),'utf8'));
    assert.equal(result.outcome,'completed');assert.equal(result.records.filter(r=>!r.warmup&&r.phase==='combined').length,8);
    assert.equal(result.summary['single/usb/tcp/up/'].mbps.median,8);
    assert.equal(result.summary['single/usb/tcp/up/'].mbps.count,2);
    assert.equal(delays[0],60000);assert.equal(result.records[0].id,'0001');
    assert.deepEqual([...pingTargets].sort(),['1.2.3.4',...paths.map(p=>p.gateway)].sort());
    assert.equal(result.pings.filter(p=>p.id==='start-delay').length,4);
    assert.ok(result.pings.every(p=>p.events.length===2&&p.started&&p.ended));
    assert.match(await readFile(path.join(dir,'ping.ndjson'),'utf8'),/"target":"board"/);
    assert.ok((await readdir(dir)).includes('0001-usb-board.ping.txt'));
    assert.ok((await readFile(path.join(dir,'status.ndjson'),'utf8')).includes('temperature_c'));
    assert.match(await readFile(path.join(dir,'report.md'),'utf8'),/completed/);
    fail=true;
    assert.equal(await main(['server','--quick','--out',parent],dependencies),1);
    assert.equal(closes,2);dirs=await readdir(parent);
    const failed=[];for(const d of dirs)failed.push(JSON.parse(await readFile(path.join(parent,d,'result.json'),'utf8')));
    assert.ok(failed.some(r=>r.outcome==='failed'&&r.records[0].error.includes('server busy')));
    fail='interrupt';
    assert.equal(await main(['server','--quick','--out',parent],dependencies),130);
    assert.equal(closes,3);
    const interrupted=[];for(const d of await readdir(parent))interrupted.push(JSON.parse(await readFile(path.join(parent,d,'result.json'),'utf8')));
    assert.ok(interrupted.some(r=>r.outcome==='interrupted'&&r.records.length===1));
    assert.equal(await main(['server','--quick','--out',parent],{...dependencies,checked:async()=>{throw Error('ENOENT');}}),1);
    assert.equal(closes,3); // Dependency failure must not start remote servers.
    const errors=[];for(const d of await readdir(parent))errors.push(JSON.parse(await readFile(path.join(parent,d,'result.json'),'utf8')));
    assert.ok(errors.some(r=>r.error?.includes('brew install iperf3')));
    const discovery={candidates:paths,errors:['en0: timeout'],detectedPaths:[paths[0]]};
    assert.equal(await main(['server','--quick','--out',parent],{...dependencies,discoverBoard:async()=>{
      const e=Error('Requested paths=both, found: usb');
      e.boardInitial={...fixture(),token:'DO_NOT_SAVE'};e.discovery=discovery;throw e;
    }}),1);
    assert.equal(closes,3);
    let missingPath;
    for(const d of await readdir(parent)) {
      const r=JSON.parse(await readFile(path.join(parent,d,'result.json'),'utf8'));
      if(r.discovery)missingPath=r;
    }
    assert.equal(missingPath.board.build,'test-build');
    assert.deepEqual(missingPath.discovery,discovery);
    assert.equal(missingPath.records.length,0);
    assert.ok(!JSON.stringify(missingPath).includes('DO_NOT_SAVE'));
    fail=false;
    assert.equal(await main(['server','--quick','--out',parent],{...dependencies,command:async(bin,args,opts)=>{
      const raw=await dependencies.command(bin,args,opts);
      if(bin==='iperf3') {
        assert.equal(opts.env.DYLD_INSERT_LIBRARIES,'/tmp/test-bind.dylib');
        assert.equal(opts.env.MESHPN_IPERF_IFACE,'en7');
        raw.stderr=''; // A successful but unbound client must never pass preflight.
      }
      return raw;
    }}),1);
    assert.equal(closes,4);
    // Non-zero ICMP loss is a warning even though ping and iperf exit zero.
    assert.equal(await main(['server','--quick','--out',parent],{...dependencies,command:async(bin,args,opts)=>{
      const raw=await dependencies.command(bin,args,opts);
      if(bin==='/sbin/ping')raw.stdout=pingText.replace('0.0% packet loss','13.3% packet loss');
      return raw;
    }}),2); // Runner reserves exit 2 for completed-with-warnings.
    assert.equal(closes,5);
    const warned=[];for(const d of await readdir(parent))warned.push(JSON.parse(await readFile(path.join(parent,d,'result.json'),'utf8')));
    assert.ok(warned.some(r=>r.outcome==='completed-with-warnings'&&r.warnings.some(w=>w.includes('ping packet loss'))));
    const sweepCommands=[];let injectedTiming=false;
    assert.equal(await main(['server','--usb-down-sweep','--out',parent],{...dependencies,
      discoverBoard:async(o)=>{assert.equal(o.paths,'usb');const b=await dependencies.discoverBoard();return {...b,paths:[paths[0]]};},
      startServers:async(o,count)=>{assert.equal(count,1);return {ports:[5201],assertAlive(){},async close(){closes++;}};},
      command:async(bin,args,opts)=>{
        if(bin==='iperf3') {
          sweepCommands.push(args);assert.ok(args.includes('-R'));
          assert.equal(args[args.indexOf('-B')+1],paths[0].address);
          assert.equal(args[args.indexOf('-p')+1],'5201');
        }
        const raw=await dependencies.command(bin,args,opts);
        if(bin==='iperf3'&&args.includes('-u')&&args[args.indexOf('-t')+1]==='15'&&!injectedTiming) {
          injectedTiming=true;
          const j=structuredClone(tailStall);j.start.connected[0].local_host=paths[0].address;
          raw.stdout=JSON.stringify(j);
        }
        return raw;
      }}),2); // Timing warnings alone must change the outcome, not the measurements.
    assert.equal(closes,6);assert.equal(sweepCommands.length,26);
    assert.equal(sweepCommands.filter(a=>a.includes('-u')).length,25); // One TCP download preflight only.
    let sweep;
    for(const d of await readdir(parent)) {
      const r=JSON.parse(await readFile(path.join(parent,d,'result.json'),'utf8'));
      if(r.options.usbDownSweep) {
        sweep=r;
        assert.match(await readFile(path.join(parent,d,'report.md'),'utf8'),/USB download rate sweep/);
      }
    }
    assert.equal(sweep.records.filter(r=>!r.warmup).length,18);
    assert.equal(sweep.records.filter(r=>r.phase==='usb-down-sweep'&&r.warmup).length,6);
    assert.equal(sweep.usb_down_sweep.length,6);
    assert.ok(sweep.usb_down_sweep.every(r=>r.n===3&&r.sender_mbps.median===9));
    assert.equal(sweep.outcome,'completed-with-warnings');
    assert.ok(sweep.warnings.some(w=>w.includes('iperf timing anomalies')));
    assert.equal(sweep.records.filter(r=>r.timing?.warnings.length).length,1);
    assert.ok(sweep.records.some(r=>r.mbps===tailStall.end.sum_received.bits_per_second/1e6&&r.timing.zero_receive_intervals?.length===1));
    assert.equal(sweep.blackouts.length,1);
    assert.equal(await main(['server','--quick','--start-delay','60','--out',parent],{...dependencies,
      delay:async()=>{process.emit('SIGINT');throw Error('Interrupted');}}),130);
    assert.equal(closes,7);
    const delayReports=await Promise.all((await readdir(parent)).map(async d=>JSON.parse(await readFile(path.join(parent,d,'result.json'),'utf8'))));
    assert.ok(delayReports.some(r=>r.outcome==='interrupted'&&r.options.startDelay===60&&r.records.length===0));
    assert.equal(process.listenerCount('SIGINT'),signalsBefore);
  }finally{await rm(parent,{recursive:true,force:true});}
});

test('partial report tolerates missing telemetry',()=>{
  assert.match(reportMarkdown({outcome:'failed',target:'test',warnings:[],error:'preflight'}),/preflight/);
});
