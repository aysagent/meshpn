// All interfaces, routes and qdiscs below belong exclusively to this NIC-less VM.
// Node owns configuration/metrics; C++ generates and verifies application data.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {execFileSync,spawn} from 'node:child_process';
import {setTimeout as pause} from 'node:timers/promises';
import {randomBytes,createHash} from 'node:crypto';
assert.match(fs.readFileSync('/proc/cmdline','utf8'),/\bmeshpn.h2-goodput=1\b/);
assert.deepEqual(fs.readdirSync('/sys/class/net'),['lo']);
const run=(file,args)=>execFileSync(file,args,{encoding:'utf8',timeout:10000});
const ip=(...args)=>run('/usr/sbin/ip',args),nip=(n,...args)=>ip('-n',n,...args);
const tc=(n,...args)=>n?ip('netns','exec',n,'/usr/sbin/tc',...args):run('/usr/sbin/tc',args);
const build='/project/native/clean_vpn/build',engine=build+'/clean-vpn-engine-fixture',work='/tmp/goodput';
fs.mkdirSync(work,{mode:0o700});const children=[];
async function until(f,ms=15000){const end=performance.now()+ms;while(!f()){assert.ok(performance.now()<end,'goodput deadline');await pause(10);}}
function start(ns,exe,args,env={}){
  const e={output:'',error:'',ended:false,events:[],pending:[],strict:false};
  const options={env:{...process.env,...env},stdio:['pipe','pipe','pipe']};delete options.env.NOTIFY_SOCKET;
  e.p=ns?spawn('/usr/sbin/ip',['netns','exec',ns,exe,...args],options):spawn(exe,args,options);
  e.p.stdout.on('data',b=>{e.output+=b;if(e.output.length>1024*1024)e.p.kill('SIGKILL');});
  e.p.stderr.on('data',b=>{e.error+=b;if(e.error.length>1024*1024)e.p.kill('SIGKILL');});
  e.p.on('error',err=>{e.error+=err.message;e.ended=true;});
  e.p.on('close',(code,signal)=>{e.code=code;e.signal=signal;e.ended=true;});children.push(e);return e;
}
const last=e=>JSON.parse(e.output.trim().split('\n').at(-1));
const tunBytes=()=>['rx_bytes','tx_bytes'].reduce((sum,key)=>sum+Number(fs.readFileSync('/sys/class/net/tun0/statistics/'+key,'utf8')),0);
function proc(pid){
  const base='/proc/'+pid,stat=fs.readFileSync(base+'/stat','utf8'),parts=stat.slice(stat.lastIndexOf(')')+2).split(' ');
  return {start:parts[19],ticks:Number(parts[11])+Number(parts[12]),rssKiB:Number(fs.readFileSync(base+'/status','utf8').match(/^VmRSS:\s+(\d+)/m)?.[1]),fds:fs.readdirSync(base+'/fd').length};
}
function retrans(pid){const lines=fs.readFileSync('/proc/'+pid+'/net/snmp','utf8').split('\n').filter(s=>s.startsWith('Tcp:')).map(s=>s.split(/\s+/));return Number(lines[1][lines[0].indexOf('RetransSegs')]);}
async function status(e){
  assert.ok(!e.ended,e.error);const at=e.output.length;e.p.stdin.write('{"op":"status"}\n');
  let s;await until(()=>{assert.ok(!e.ended,e.error);const lines=e.output.slice(at).split('\n');lines.pop();
    for(const l of lines){const event=JSON.parse(l);assert.equal(event.state,'ready','unexpected reconnect');if(event.event==='status')s=event;}
    return !!s;},2000);return s;
}
async function stopEngine(e){e.p.stdin.write('{"op":"stop"}\n');await until(()=>e.ended);assert.equal(e.code,0,e.error);}
function tun(ns,addr){const call=(...a)=>ns?nip(ns,...a):ip(...a);call('tuntap','add','dev','tun0','mode','tun');call('addr','add',addr,'dev','tun0');call('link','set','tun0','mtu','1400','up');}
function shape(link){for(let i=1;i<=4;i++)for(const [ns,dev] of [[null,'wan'+i],['gp'+i,'wan0']])
  tc(ns,'qdisc','replace','dev',dev,'root','netem','limit','10000','delay',link.rttMs/2+'ms','rate',link.mbps+'mbit');}
function qdiscs(){const out=[];for(let i=1;i<=4;i++)for(const [ns,dev] of [[null,'wan'+i],['gp'+i,'wan0']])out.push({ns,dev,qdisc:JSON.parse(tc(ns,'-s','-j','qdisc','show','dev',dev))});return out;}
const cases=[],calibration=[];
let origin;
try{
  tun(null,'10.99.0.1/24');
  for(let i=1;i<=4;i++){
    const ns='gp'+i;ip('netns','add',ns);ip('link','add','wan'+i,'type','veth','peer','name','peer'+i);
    ip('link','set','peer'+i,'netns',ns);nip(ns,'link','set','peer'+i,'name','wan0');nip(ns,'link','set','lo','up');
    ip('addr','add',`198.18.${i}.1/30`,'dev','wan'+i);ip('link','set','wan'+i,'up');
    nip(ns,'addr','add',`198.18.${i}.2/30`,'dev','wan0');nip(ns,'link','set','wan0','up');
    tun(ns,`10.99.0.${i+1}/32`);nip(ns,'route','add','10.99.0.1/32','dev','tun0');
  }
  // No forward/NAT/default routes: the TCP origin is local to exit's TUN address.
  run('/usr/bin/openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',work+'/key.pem','-out',work+'/cert.pem','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost']);
  fs.chmodSync(work+'/key.pem',0o600);
  const profile=JSON.parse(fs.readFileSync('/project/fixtures/native-tls-profiles/cold-alps.json'));
  profile.http2.connection_window=1048576;profile.http2.settings.find(([id])=>id===4)[1]=1048576;
  fs.writeFileSync(work+'/profile.json',JSON.stringify(profile));
  const peers=[];
  for(let i=1;i<=4;i++){
    const secret_path=work+'/psk'+i,ipv4=`10.99.0.${i+1}`;fs.writeFileSync(secret_path,randomBytes(32),{mode:0o600});peers.push({ipv4,secret_path});
    fs.writeFileSync(work+'/client'+i+'.json',JSON.stringify({version:1,role:'client',address:`198.18.${i}.1`,port:9443,tun:'tun0',dns:false,peer_ipv4:ipv4,secret_path,ca:work+'/cert.pem',server_name:'localhost',tls_profile_path:work+'/profile.json'}));
  }
  fs.writeFileSync(work+'/exit.json',JSON.stringify({version:1,role:'exit',address:'0.0.0.0',port:9443,tun:'tun0',dns:false,peers,cert:work+'/cert.pem',key:work+'/key.pem'}));
  for(const config of ['exit','client1'])run(build+'/clean-vpn-engine',['--check-config',work+'/'+config+'.json']);
  origin=start(null,build+'/h2-goodput-test',['server']);await until(()=>{assert.ok(!origin.ended,origin.error);return origin.output.includes('H2_ORIGIN_READY');});
  async function transfer(kind,address){const job=start('gp1',build+'/h2-goodput-test',[kind,address]);await until(()=>job.ended,60000);assert.equal(job.code,0,job.error);const result=last(job);assert.equal(result.verified,true);assert.equal(result.bytes,8388608);return result;}
  // Unshaped direct TCP controls bound what this TCG fixture can deliver.
  for(const kind of ['download','upload'])calibration.push({link:'unshaped',...(await transfer(kind,'198.18.1.1'))});
  for(const link of [{mbps:20,rttMs:40},{mbps:100,rttMs:120}]){
    shape(link);const beforeQ=qdiscs();
    const ping=ip('netns','exec','gp1','/bin/busybox','ping','-n','-c','5','-W','2','198.18.1.1');
    const match=/round-trip min\/avg\/max = ([\d.]+)\/([\d.]+)\/([\d.]+)/.exec(ping);assert.ok(match);
    const rttMs={min:+match[1],avg:+match[2],max:+match[3]};assert.ok(rttMs.min>=link.rttMs*.9);
    for(const kind of ['download','upload'])calibration.push({link,rttMs,...(await transfer(kind,'198.18.1.1'))});
    for(let repetition=1;repetition<=3;repetition++)for(const mode of repetition%2?['baseline','browser-credit']:['browser-credit','baseline']){
      const env={CVPN_TEST_H2_BUDGET:mode,CVPN_TEST_H2_OBSERVER:'1'};
      const ex=start(null,engine,['--config',work+'/exit.json'],env);
      await until(()=>{assert.ok(!ex.ended,ex.error);return ex.output.includes('"state":"listening"');});
      const engines=[ex];for(let i=1;i<=4;i++)engines.push(start('gp'+i,engine,['--config',work+'/client'+i+'.json'],env));
      await until(()=>engines.every(e=>{assert.ok(!e.ended,e.error);return e.output.includes('"state":"ready"');}));
      for(const kind of ['download','upload']){
        console.error('H2_GOODPUT_CASE='+JSON.stringify({link,repetition,mode,kind}));
        const probes=[2,3,4].map(i=>start('gp'+i,build+'/h2-goodput-test',['probe','10.99.0.1']));
        await until(()=>probes.every(e=>{assert.ok(!e.ended,e.error);return e.output.includes('H2_PROBE_READY');}));
        const before=engines.map(e=>proc(e.p.pid)),beforeDrop=await Promise.all(engines.map(status));
        const retransBefore=engines.reduce((sum,e)=>sum+retrans(e.p.pid),0),beforeTun=tunBytes(),samples=[];
        const job=start('gp1',build+'/h2-goodput-test',[kind,'10.99.0.1']);
        const began=performance.now();
        do{
          assert.ok(performance.now()-began<60000,'transfer deadline');
          assert.ok(probes.every(e=>!e.ended),'probe exited under load');
          const states=await Promise.all(engines.map(status));const resources=engines.map(e=>proc(e.p.pid));
          for(let i=0;i<states.length;i++){
            const s=states[i].fixture_h2_budget;assert.equal(s.live_sessions,i?1:4);assert.equal(s.socket_memory_samples,s.live_sessions);
            assert.ok(s.largest_queue_bytes<=1048576);assert.ok(resources[i].rssKiB<128*1024);assert.equal(resources[i].start,before[i].start);
          }
          samples.push({states,resources});if(!job.ended)await pause(100);
        }while(!job.ended);
        const wallSeconds=(performance.now()-began)/1000;assert.equal(job.code,0,job.error);const result=last(job);assert.equal(result.verified,true);
        assert.equal(result.bytes,8388608);assert.equal(result.kind,kind);assert.ok(result.goodputMbps>0&&result.endMs>result.startMs);
        const exitTunBytes=tunBytes()-beforeTun;assert.ok(exitTunBytes>=result.bytes,'bulk did not traverse real TUN');
        for(const p of probes)p.p.kill('SIGTERM');await until(()=>probes.every(p=>p.ended));
        const health=probes.map(p=>{assert.equal(p.code,0,p.error);const samples=last(p).samples.filter(s=>s.startMs>=result.startMs&&s.endMs<=result.endMs).map(s=>s.endMs-s.startMs).sort((a,b)=>a-b);assert.ok(samples.length>=3,'insufficient concurrent probes');return {samples:samples.length,medianMs:samples[Math.floor(samples.length/2)],p95Ms:samples[Math.ceil(samples.length*.95)-1],maxMs:samples.at(-1)};});
        const after=engines.map(e=>proc(e.p.pid));
        const metrics={sampleCount:samples.length,wallSeconds,exitTunBytes,engineCpuTicks:after.map((s,i)=>s.ticks-before[i].ticks),
          peakRssKiB:engines.map((_,i)=>Math.max(...samples.map(s=>s.resources[i].rssKiB))),
          peakTcpSendQueuedBytes:Math.max(...samples.map(s=>s.states.reduce((a,e)=>a+e.fixture_h2_budget.tcp_send_queued_bytes,0))),
          peakTcpReceiveAllocBytes:Math.max(...samples.map(s=>s.states.reduce((a,e)=>a+e.fixture_h2_budget.tcp_receive_alloc_bytes,0))),
          droppedPackets: samples.at(-1).states.map((s,i)=>s.dropped_packets-beforeDrop[i].dropped_packets),
          tcpRetransSegmentsAllNamespaces:engines.reduce((sum,e)=>sum+retrans(e.p.pid),0)-retransBefore};
        cases.push({link,rttMs,repetition,mode,...result,health,metrics});
      }
      // Verify the actual advertised initial stream/connection credit, not just config.
      const wire=ex.error.split('\n').filter(l=>l.startsWith('fixture_h2 ')).map(l=>JSON.parse(l.slice(11))).filter(r=>r.kind==='wire'&&r.receiver==='exit').map(r=>Buffer.from(r.hex,'hex'));
      const settings=wire.filter(b=>b[3]===4&&!(b[4]&1)),updates=wire.filter(b=>b[3]===8&&b.readUInt32BE(5)===0);
      assert.equal(settings.length,4);assert.equal(updates.length,4);
      for(const b of settings){const pairs=[];for(let at=9;at<b.length;at+=6)pairs.push([b.readUInt16BE(at),b.readUInt32BE(at+2)]);assert.equal(pairs.find(([id])=>id===4)[1],mode==='baseline'?1048576:6291456);}
      for(const b of updates)assert.equal(b.readUInt32BE(9),mode==='baseline'?1048576-65535:15728640-65535);
      for(const e of engines.slice(1))await stopEngine(e);await stopEngine(ex);
    }
    const afterQ=qdiscs();calibration.push({link,rttMs,qdiscBefore:beforeQ,qdiscAfter:afterQ});
  }
  origin.p.kill('SIGTERM');await until(()=>origin.ended);assert.equal(origin.code,0,origin.error);
  console.log('H2_KERNEL_REPORT='+JSON.stringify({schema:1,kind:'clean-vpn-native-h2-goodput-report',status:'passed',
    realTun:true,clients:4,bulkClients:1,repetitions:3,nic:'none',hostSharedFilesystem:false,productionWindowIncreaseApproved:false,
    productionCapsChanged:false,physicalHostsTouched:false,calibration,cases,
    binaries:Object.fromEntries(['clean-vpn-engine','clean-vpn-engine-fixture','h2-goodput-test'].map(n=>[n,createHash('sha256').update(fs.readFileSync(build+'/'+n)).digest('hex')])),
    limitations:['TCG-not-hardware-ceiling','per-client-full-duplex-link-not-shared-access-bottleneck','8MiB-completion-not-steady-state',
      'no-random-loss-model','DNS-disabled-in-lab','sampled-RSS-and-TCP-counters-not-total-kernel-memory','upload-is-control-client-receive-credit-only']}));
}finally{for(const e of children)if(!e.ended)e.p.kill('SIGKILL');}
