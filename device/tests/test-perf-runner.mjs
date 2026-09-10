import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import http from 'node:http';
import net from 'node:net';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { parseArgs, quote, command, iperfArgs, parseIperf, stats, parsePing, summarize,
  measurementPlan, counterDelta, macRoute, sameSubnet, remoteServer } from '../scripts/perf-lib.mjs';
import { discoverBoard, checkRoute, requestBoard, sshArgs } from '../scripts/perf-network.mjs';
import { executeSchedule, cleanStatus, telemetrySummary, reportMarkdown, main } from '../scripts/perf-runner.mjs';

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

test('interface binding, direction and UDP packet size are explicit',()=>{
  const args=iperfArgs('1.2.3.4',5202,paths[1],{seconds:30,protocol:'udp',direction:'down',rate:10});
  for(const flag of ['-4','-R','--get-server-output','-J','--bind-dev','-B'])assert.ok(args.includes(flag));
  assert.equal(args[args.indexOf('--bind-dev')+1],'en0');assert.equal(args[args.indexOf('-B')+1],paths[1].address);
  assert.equal(args[args.indexOf('-l')+1],'1200');assert.equal(args[args.indexOf('-b')+1],'10M');
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
  let ticks=0;
  const dependencies={platform:'darwin',log:()=>{},lookup:async()=>({address:'1.2.3.4'}),delay:async()=>{},
    checked:async(bin,args)=>bin==='iperf3'?(args.includes('--help')?'--bind-dev':'iperf3 test'):'test',
    discoverBoard:async()=>({paths,initial:fixture(),status:async()=>{const f=fixture();f.uptime_sec+=ticks++;f.cpu.sampled_us+=ticks*2000000;return f;}}),
    checkRoute:async()=> 'validated test route',spawn:()=>({on(){},kill(){}}),
    startServers:async()=>({ports:[5201,5202],assertAlive(){},async close(){closes++;}}),
    command:async(bin,args)=>{
      if(bin==='ssh')return {code:0,stdout:'iperf3 test\nPython 3 test',stderr:''};
      if(bin==='/sbin/ping')return {code:0,stdout:pingText,stderr:''};
      assert.equal(bin,'iperf3');portsSeen.add(args[args.indexOf('-p')+1]);
      if(fail==='interrupt'){process.emit('SIGINT');throw Error('Interrupted');}
      return fail?{code:1,stdout:'{"error":"test server busy"}',stderr:''}:
        {code:0,stdout:iperfJSON(args[args.indexOf('-B')+1],args.includes('-u')),stderr:''};
    }};
  try {
    assert.equal(await main(['user@server:2222','--quick','--out',parent],dependencies),0);
    assert.equal(closes,1);assert.deepEqual([...portsSeen].sort(),['5201','5202']);
    let dirs=await readdir(parent);const dir=path.join(parent,dirs[0]);
    const result=JSON.parse(await readFile(path.join(dir,'result.json'),'utf8'));
    assert.equal(result.outcome,'completed');assert.equal(result.records.filter(r=>!r.warmup&&r.phase==='combined').length,8);
    assert.equal(result.summary['single/usb/tcp/up/'].mbps.median,8);
    assert.equal(result.summary['single/usb/tcp/up/'].mbps.count,2);
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
    assert.equal(process.listenerCount('SIGINT'),signalsBefore);
  }finally{await rm(parent,{recursive:true,force:true});}
});

test('partial report tolerates missing telemetry',()=>{
  assert.match(reportMarkdown({outcome:'failed',target:'test',warnings:[],error:'preflight'}),/preflight/);
});
