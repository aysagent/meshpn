import { spawn } from 'node:child_process';
import { isIP } from 'node:net';

export function parseArgs(args) {
  const o = { seconds:30, runs:5, soakMinutes:30, idleSeconds:30, iperfPort:5201, paths:'auto' };
  const names = {'seconds':'seconds','runs':'runs','soak-minutes':'soakMinutes','idle-seconds':'idleSeconds',
    'iperf-port':'iperfPort','server-ip':'serverIP','paths':'paths','admin-url':'adminURL','admin-ca':'adminCA','out':'out'};
  for(let i=0;i<args.length;i++) {
    const a=args[i];
    if(a==='--help'||a==='-h') o.help=true;
    else if(a==='--quick') Object.assign(o,{seconds:3,runs:2,soakMinutes:0,idleSeconds:3});
    else if(a==='--admin-insecure') o.adminInsecure=true;
    else if(a.startsWith('--')&&names[a.slice(2)]) {
      if(!args[i+1]||args[i+1].startsWith('--')) throw Error(`Missing value: ${a}`);
      o[names[a.slice(2)]]=args[++i];
    } else if(a.startsWith('-')||o.target) throw Error(`Unknown argument: ${a}`);
    else o.target=a;
  }
  if(o.help) return o;
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
  return {mbps:receiver.bits_per_second/1e6,retransmits:j.end?.sum_sent?.retransmits??null,
    lost_percent:receiver.lost_percent??null,jitter_ms:receiver.jitter_ms??null,
    local_address:j.start?.connected?.[0]?.local_host??null};
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

export function counterDelta(before,after) {
  const reset=!before||!after||after.uptime_sec<before.uptime_sec;
  return Object.fromEntries(['usb.tx_ok','usb.tx_dropped','usb.tx_retried','usb.tx_no_host','net.ap_ip4_rx','net.lan_ip4_rx'].map(key=>{
    const [group,field]=key.split('.'),a=before?.[group]?.[field],b=after?.[group]?.[field];
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
