import { spawn } from 'node:child_process';
import { isIP } from 'node:net';

export function parseArgs(args) {
  const o = { seconds:30, runs:5, soakMinutes:30, idleSeconds:30, iperfPort:5201, paths:'auto' };
  if(args.includes('--usb-down-sweep'))Object.assign(o,{usbDownSweep:true,seconds:15,runs:3,soakMinutes:0,idleSeconds:10,paths:'usb'});
  const names = {'seconds':'seconds','runs':'runs','soak-minutes':'soakMinutes','idle-seconds':'idleSeconds',
    'iperf-port':'iperfPort','server-ip':'serverIP','paths':'paths','admin-url':'adminURL','admin-ca':'adminCA','out':'out'};
  for(let i=0;i<args.length;i++) {
    const a=args[i];
    if(a==='--help'||a==='-h') o.help=true;
    else if(a==='--usb-down-sweep') o.usbDownSweep=true;
    else if(a==='--quick') Object.assign(o,{seconds:3,runs:2,soakMinutes:0,idleSeconds:3});
    else if(a==='--admin-insecure') o.adminInsecure=true;
    else if(a.startsWith('--')&&names[a.slice(2)]) {
      if(!args[i+1]||args[i+1].startsWith('--')) throw Error(`Missing value: ${a}`);
      o[names[a.slice(2)]]=args[++i];
    } else if(a.startsWith('-')||o.target) throw Error(`Unknown argument: ${a}`);
    else o.target=a;
  }
  if(o.help) return o;
  if(o.usbDownSweep&&(args.includes('--quick')||o.paths!=='usb'||Number(o.seconds)!==15||Number(o.runs)!==3||Number(o.soakMinutes)!==0))
    throw Error('--usb-down-sweep requires USB only, 15s, 3 repeats, no soak; do not combine with --quick or conflicting timing/path options');
  if(!o.target) throw Error('Pass SSH target: user@192.168.1.100:22');
  // No arbitrary SSH options, shell syntax, or IPv6 (the dongle routes IPv4).
  const m=/^(?:([a-zA-Z0-9_][a-zA-Z0-9_.-]*)@)?([a-zA-Z0-9][a-zA-Z0-9.-]*)(?::([0-9]+))?$/.exec(o.target);
  if(!m) throw Error('Expected [user@]IPv4-or-hostname[:SSH-port]');
  o.host=m[2];o.sshTarget=(m[1]?m[1]+'@':'')+m[2];o.sshPort=Number(m[3]||22);
  for(const [key,min,max] of [['sshPort',1,65535],['iperfPort',1024,65534],['seconds',1,300],['runs',1,20],['soakMinutes',0,120],['idleSeconds',1,600]]) {
    o[key]=Number(o[key]);
    if(!Number.isInteger(o[key])||o[key]<min||o[key]>max) throw Error(`Invalid ${key}: ${min}..${max}`);
  }
  if(!['auto','usb','ap','both'].includes(o.paths)) throw Error('--paths must be auto, usb, ap or both');
  if(o.serverIP&&isIP(o.serverIP)!==4) throw Error('--server-ip must be IPv4');
  return o;
}
export const quote = s => "'"+String(s).replaceAll("'", "'\\''")+"'";
export function command(bin,args,{timeout=15000,signal,input,env}={}) {
  return new Promise((resolve,reject)=>{
    const p=spawn(bin,args,{stdio:['pipe','pipe','pipe'],env:env||process.env});
    let stdout='',stderr='',failure,killTimer;
    const stop=()=>{p.kill('SIGTERM');killTimer=setTimeout(()=>p.kill('SIGKILL'),1500);killTimer.unref();};
    const abort=()=>{failure=Error('Interrupted');stop();};
    const timer=setTimeout(()=>{failure=Error(`${bin}: timeout after ${timeout}ms`);stop();},timeout);
    signal?.addEventListener('abort',abort,{once:true});
    p.on('error',e=>{failure=e;});
    p.stdout.on('data',b=>{stdout+=b;if(stdout.length>16*1024*1024){failure=Error('Excessive process output');stop();}});
    p.stderr.on('data',b=>{stderr=(stderr+b).slice(-1024*1024);});
    p.on('close',(code)=>{clearTimeout(timer);clearTimeout(killTimer);signal?.removeEventListener('abort',abort);
      if(failure) {failure.stdout=stdout;failure.stderr=stderr;reject(failure);} else resolve({code,stdout,stderr});});
    p.stdin.on('error',()=>{});p.stdin.end(input);
    if(signal?.aborted)abort();
  });
}
export async function checked(bin,args,opts) {
  const r=await command(bin,args,opts);
  if(r.code!==0) throw Error(`${bin} exited ${r.code}: ${r.stderr.trim()||r.stdout.trim()}`);
  return r.stdout;
}
export function iperfArgs(server,port,path,test) {
  return ['-4','-c',server,'-p',String(port),'-B',path.address,
    '-t',String(test.seconds),'-J','--get-server-output','--connect-timeout','8000',
    ...(test.direction==='down'?['-R']:[]),...(test.protocol==='udp'?['-u','-b',`${test.rate}M`,'-l','1200']:[])];
}
export function parseIperf(text,protocol) {
  const j=JSON.parse(text);
  if(j.error)throw Error(j.error);
  let receiver=j.end?.sum_received;
  // Older iperf3 versions expose UDP receiver stats per stream or in server JSON.
  if(protocol==='udp'&&!receiver) {
    const candidates=[j.end?.sum,...(j.end?.streams||[]).map(s=>s.udp),j.server_output_json?.end?.sum];
    receiver=candidates.find(s=>s&&s.sender===false);
  }
  if(!receiver||!Number.isFinite(receiver.bits_per_second)) throw Error('No receiver throughput in iperf3 JSON');
  return {mbps:receiver.bits_per_second/1e6,sender_mbps:Number.isFinite(j.end?.sum_sent?.bits_per_second)?j.end.sum_sent.bits_per_second/1e6:null,
    retransmits:j.end?.sum_sent?.retransmits??null,
    lost_percent:receiver.lost_percent??null,jitter_ms:receiver.jitter_ms??null,
    timing:iperfTiming(j,receiver),
    local_address:j.start?.connected?.[0]?.local_host??null};
}

// Diagnostics only: never replace receiver throughput/loss or remove a run.
export function iperfTiming(j, receiver) {
  const seconds=s=>Number.isFinite(s?.seconds)&&s.seconds>0?s.seconds:null;
  const sender=j.end?.sum_sent||[j.server_output_json?.end?.sum,j.end?.sum].find(s=>s?.sender===true);
  const senderSeconds=seconds(sender),receiverSeconds=seconds(receiver);
  const delta=senderSeconds!==null&&receiverSeconds!==null?senderSeconds-receiverSeconds:null;
  const durationTolerance=receiverSeconds!==null?Math.max(0.5,receiverSeconds*0.05):null;
  const receiverIntervals=source=>(source?.intervals||[]).map(i=>i.sum)
    .filter(s=>s?.sender===false&&s.omitted!==true&&Number.isFinite(s.bytes)&&s.bytes>=0&&Number.isFinite(s.start)&&Number.isFinite(s.end)&&s.end>s.start&&seconds(s)!==null);
  const local=receiverIntervals(j),remote=receiverIntervals(j.server_output_json);
  const intervals=local.length?local:remote;
  // Missing bytes are not zero. Keep short zero intervals too, but do not warn on them.
  const zero=intervals.filter(s=>s.bytes===0).map(s=>({start:s.start,end:s.end,seconds:s.seconds}));
  const warnings=[];
  if(delta!==null&&Math.abs(delta)>durationTolerance)warnings.push('duration_mismatch');
  if(zero.some(s=>s.seconds>=0.5))warnings.push('zero_receive_interval');
  return {sender_seconds:senderSeconds,receiver_seconds:receiverSeconds,duration_delta_seconds:delta,
    duration_tolerance_seconds:durationTolerance,zero_warning_min_seconds:0.5,
    requested_seconds:seconds({seconds:j.start?.test_start?.duration}),
    receiver_interval_source:local.length?'client':remote.length?'server':null,
    receiver_interval_count:intervals.length||null,zero_receive_intervals:intervals.length?zero:null,
    client_version:typeof j.start?.version==='string'?j.start.version:null,
    server_version:typeof j.server_output_json?.start?.version==='string'?j.server_output_json.start.version:null,warnings};
}
export function stats(values) {
  const a=values.filter(Number.isFinite).sort((a,b)=>a-b);
  if(!a.length)return null;
  const percentile=p=>{const i=(a.length-1)*p,k=Math.floor(i);return a[k]+(a[Math.ceil(i)]-a[k])*(i-k);};
  return {count:a.length,min:a[0],median:percentile(.5),p95:percentile(.95),max:a.at(-1)};
}
export function parsePing(text) {
  const times=[...text.matchAll(/time[=<]([\d.]+)\s*ms/g)].map(m=>Number(m[1]));
  const loss=/([\d.]+)% packet loss/.exec(text);
  return {rtt_ms:stats(times),loss_percent:loss?Number(loss[1]):null};
}
export function summarize(records) {
  const groups={};
  for(const r of records.filter(r=>!r.warmup)) {
    const key=[r.phase,r.path,r.protocol,r.direction,r.rate||''].join('/');
    const g=groups[key]??={mbps:[],loss:[],jitter:[],retransmits:[],failed:0};
    if(r.error)g.failed++;
    else {g.mbps.push(r.mbps);g.loss.push(r.lost_percent);g.jitter.push(r.jitter_ms);g.retransmits.push(r.retransmits);}
  }
  return Object.fromEntries(Object.entries(groups).map(([k,g])=>[k,{mbps:stats(g.mbps),loss:stats(g.loss),jitter:stats(g.jitter),retransmits:stats(g.retransmits),failed:g.failed}]));
}

// One warm-up per scenario/direction; repetitions interleave up/down to reduce drift.
export function measurementPlan(paths, o) {
  const plan=[];
  if(o.usbDownSweep) {
    if(paths.length!==1||paths[0].kind!=='usb')throw Error('USB download sweep requires exactly one USB path');
    for(const rate of [5,6,7,8,9,10])for(let run=0;run<=o.runs;run++)
      plan.push({paths,protocol:'udp',direction:'down',rate,seconds:run===0?3:o.seconds,
        run,warmup:run===0,phase:'usb-down-sweep'});
    return plan;
  }
  const add=(selected,protocol,rate,phase)=>{
    for(let run=0;run<=o.runs;run++) for(const direction of ['up','down']) {
      plan.push({paths:selected,protocol,rate,direction,seconds:o.seconds,run,warmup:run===0,phase});
    }
  };
  for(const path of paths) {
    add([path],'tcp',null,'single');
    for(const rate of [5,10])add([path],'udp',rate,'single');
  }
  if(paths.length===2)add(paths,'tcp',null,'combined');
  return plan;
}

export const usbCounterFields = ['tx_ok','tx_dropped','tx_retried','tx_no_host','tx_timeout',
  'tx_calls','tx_attempts','tx_busy','tx_busy_exhausted','tx_no_mem','tx_invalid_state','tx_other_error',
  'tx_bytes','tx_wait_us','tx_wait_le_1ms','tx_wait_1_5ms','tx_wait_5_25ms','tx_wait_gt_25ms'];
export const ncmCounterFields = ['samples','initializations','busy','busy_no_free','busy_active',
  'ntb_started','start_errors','bytes_started','frames_started','ntb_completed','completion_errors',
  'bytes_completed','zlp_completed','zlp_errors','completion_timed','completion_us',
  'completion_le_1ms','completion_1_5ms','completion_5_25ms','completion_gt_25ms','backlog_gaps','backlog_gap_us'];
export const usbQueueCounterFields = ['submitted','enqueued','completed','sent','send_failed','full','no_host',
  'invalid_length','not_ready','enqueue_failed','expired','stale','bytes_copied','init_failed','queue_wait_us','residence_us',
  'capacity_waits','capacity_wakeups','capacity_timeouts','capacity_disconnects','capacity_wait_us'];

export function hasPingProblem(pings) {
  return pings.some(p => p.error || (Number.isFinite(p.loss_percent) && p.loss_percent > 0));
}

// Strict sums: a missing/reset counter window is unknown, never zero losses.
export function summarizeUsbDownSweep(records, pings=[]) {
  const losses=['full','no_host','invalid_length','not_ready','enqueue_failed','expired','stale','send_failed'];
  return [5,6,7,8,9,10].map(rate=>{
    const all=records.filter(r=>r.phase==='usb-down-sweep'&&r.path==='usb'&&r.protocol==='udp'&&r.direction==='down'&&!r.warmup&&r.rate===rate);
    const good=all.filter(r=>!r.error), ids=new Set(good.map(r=>r.id));
    const ping=pings.filter(p=>p.path==='usb'&&ids.has(p.id)&&!p.error);
    const sum=keys=>{
      const values=good.flatMap(r=>keys.map(k=>r.batch_counters?.[`usb.tx_queue.${k}`]));
      return values.length&&values.every(Number.isFinite)?values.reduce((a,b)=>a+b,0):null;
    };
    const submitted=sum(['submitted']),lost=sum(losses),completed=sum(['completed']),residence=sum(['residence_us']);
    return {rate,n:good.length,failed:all.length-good.length,
      sender_mbps:stats(good.map(r=>r.sender_mbps)),receiver_mbps:stats(good.map(r=>r.mbps)),udp_loss:stats(good.map(r=>r.lost_percent)),
      full:sum(['full']),queue_losses:lost,submitted,queue_loss_percent:lost!==null&&submitted>0?100*lost/submitted:null,
      residence_mean_ms:residence!==null&&completed>0?residence/completed/1000:null,
      ping_samples:ping.length,ping_p95_ms:stats(ping.map(p=>p.rtt_ms?.p95)),ping_loss:stats(ping.map(p=>p.loss_percent))};
  });
}

export function counterDelta(before,after) {
  const reset=!before||!after||after.uptime_sec<before.uptime_sec;
  return Object.fromEntries([...usbCounterFields.map(k=>`usb.${k}`),...ncmCounterFields.map(k=>`usb.ncm.${k}`),
    ...usbQueueCounterFields.map(k=>`usb.tx_queue.${k}`),'net.ap_ip4_rx','net.lan_ip4_rx'].map(key=>{
    const get=v=>key.split('.').reduce((o,k)=>o?.[k],v),a=get(before),b=get(after);
    return [key,!reset&&Number.isFinite(a)&&Number.isFinite(b)&&b>=a?b-a:null];
  }));
}

export function macRoute(text) {
  return {gateway:/^\s*gateway:\s*(\S+)/m.exec(text)?.[1],iface:/^\s*interface:\s*(\S+)/m.exec(text)?.[1]};
}

export function sameSubnet(address,gateway,netmask) {
  if([address,gateway,netmask].some(s=>isIP(s)!==4))return false;
  const n=s=>s.split('.').reduce((v,b)=>(v<<8)|Number(b),0);
  return (n(address)&n(netmask))===(n(gateway)&n(netmask));
}

// Runs inside one SSH session. EOF, signals, lost heartbeat or deadline reap only our children.
// No daemon, shared pidfile, firewall changes, or killall.
export const remoteServer = `import sys, subprocess, tempfile, selectors, time, signal, os
ports = [int(p) for p in sys.argv[1:]]
children = []
logs = []
def stopped(*args):
    raise KeyboardInterrupt()
for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
    signal.signal(s, stopped)
try:
    for port in ports:
        log = tempfile.TemporaryFile()
        logs.append(log)
        children.append(subprocess.Popen(['iperf3', '-s', '-4', '-J', '-p', str(port)], stdout=log, stderr=log))
    time.sleep(1)
    for p, log in zip(children, logs):
        if p.poll() is not None:
            log.seek(0)
            raise RuntimeError(log.read().decode(errors='replace'))
    print('MESHPN_READY', flush=True)
    sel = selectors.DefaultSelector()
    sel.register(sys.stdin, selectors.EVENT_READ)
    deadline = time.monotonic() + 21600
    lease_seconds = 30
    last_input = time.monotonic()
    while time.monotonic() < deadline:
        if any(p.poll() is not None for p in children):
            raise RuntimeError('iperf3 server exited unexpectedly')
        if time.monotonic() - last_input > lease_seconds:
            break
        if sel.select(1):
            if not os.read(sys.stdin.fileno(), 4096):
                break
            last_input = time.monotonic()
except KeyboardInterrupt:
    pass
finally:
    for p in children:
        if p.poll() is None:
            p.terminate()
    for p in children:
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
    for log in logs:
        log.close()
`;
