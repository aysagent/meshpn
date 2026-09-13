import { mkdir,writeFile,mkdtemp } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { discoverBoard,checkLocalRoute } from './perf-network.mjs';
import { cleanStatus } from './perf-runner.mjs';
import { counterDelta,stats,command } from './perf-lib.mjs';

export function parseLocalArgs(args) {
  const o={paths:'usb',localOnly:true,runs:3,startDelay:60};
  const names={'--runs':'runs','--start-delay':'startDelay','--admin-url':'adminURL','--admin-ca':'adminCA','--out':'out'};
  for(let i=0;i<args.length;i++) {
    const a=args[i];
    if(a==='--help'||a==='-h')o.help=true;
    else if(a==='--admin-insecure')o.adminInsecure=true;
    else if(names[a]&&args[i+1]&&!args[i+1].startsWith('-'))o[names[a]]=args[++i];
    else throw Error(`Unknown argument or missing value: ${a}`);
  }
  for(const [key,min,max] of [['runs',1,20],['startDelay',0,600]]) {
    o[key]=Number(o[key]);
    if(!Number.isInteger(o[key])||o[key]<min||o[key]>max)throw Error(`Invalid ${key}: ${min}..${max}`);
  }
  return o;
}

export function localReport(r) {
  const n=v=>Number.isFinite(v)?v.toFixed(2):'n/a';
  const mean=(m,total,count)=>{
    const a=m.counters?.[`usb.ncm.${total}`],b=m.counters?.[`usb.ncm.${count}`];
    return Number.isFinite(a)&&b>0?n(a/b):'n/a';
  };
  return `# MeshPN local USB download\n\nResult: ${r.status}\n\n`+
    `Board build: ${r.board?.build??'unknown'}; transport: ${r.transport??'unknown'}; DWC2 telemetry: ${r.board?.usb?.dwc2?.available??'unknown'}.\n\n`+
    `USB profile: ${r.board?.usb?.profile??'unknown'}; queue capacity: ${r.board?.usb?.tx_queue?.capacity??'unknown'}; event wait: ${r.board?.usb?.tx_queue?.event_wait??'unknown'}; double FIFO configured: ${r.board?.usb?.ncm_double_buffer_configured??'unknown'}.\n\n`+
    'Board-generated TCP/HTTP body → lwIP → existing USB TX queue → NCM → Mac. No WAN/SSH server or Wi-Fi uplink required. HTTPS includes TLS overhead; settings are not changed.\n\n'+
    'Each response is 8 MiB. Receiver throughput includes connection setup through complete response; warm-up excluded. No UDP loss estimate. API sampled before/after only (the HTTP worker is occupied by the stream); counters include other board traffic. Close admin browser and stop other benchmarks.\n\n'+
    `Measured successful/attempted: ${r.measurements.filter(m=>!m.warmup&&!m.error).length}/${r.measurements.filter(m=>!m.warmup).length}. Receiver median: ${n(r.receiver_mbps?.median)} Mbit/s.\n\n`+
    '| Run | Warm-up | Received bytes | Seconds | Receiver Mbit/s | Queue full | Error |\n|---|---|---:|---:|---:|---:|---|\n'+
    r.measurements.map(m=>`| ${m.run} | ${m.warmup?'yes':'no'} | ${m.bytes??'n/a'} | ${n(m.seconds)} | ${n(m.receiver_mbps)} | ${m.counters?.['usb.tx_queue.full']??'n/a'} | ${String(m.error??'').replace(/[|\r\n]/g,' ')} |`).join('\n')+
    '\n\nDevice-wide NCM deltas (including before/after API traffic and 3s recovery):\n\n'+
    '| Run | NTB completed | Bytes/NTB | Frames/NTB | Completion mean µs | Backlog gap mean µs |\n|---|---:|---:|---:|---:|---:|\n'+
    r.measurements.map(m=>`| ${m.run} | ${m.counters?.['usb.ncm.ntb_completed']??'n/a'} | ${mean(m,'bytes_completed','ntb_completed')} | ${mean(m,'frames_started','ntb_started')} | ${mean(m,'completion_us','completion_timed')} | ${mean(m,'backlog_gap_us','backlog_gaps')} |`).join('\n')+
    `\n\nWarnings: ${(r.warnings||[]).join('; ')||'none detected (no continuous telemetry/ping)'}\n`+
    `\n\n${r.error?`Stopped: ${r.error}\n`:''}`;
}

export async function main(args=process.argv.slice(2),deps={}) {
  const o=parseLocalArgs(args);
  if(o.help){console.log('Usage: npm run device:perf:usb-local -- [--start-delay 60] [--runs 3] [--admin-url http(s)://BOARD-IP/] [--admin-ca cert.pem | --admin-insecure] [--out DIRECTORY]\nMac only. Uses MESHPN_ADMIN_PASSWORD. No server argument.');return 0;}
  const log=deps.log??console.log,wait=deps.wait??((ms,signal)=>delay(ms,undefined,{signal}));
  const controller=new AbortController(),signal=controller.signal,stop=()=>controller.abort();
  process.once('SIGINT',stop);process.once('SIGTERM',stop);
  // Always create a new child: never overwrite an earlier result.
  const parent=path.resolve(o.out??fileURLToPath(new URL('../perf-results/',import.meta.url)));
  let output;
  const r={status:'failed',started:new Date().toISOString(),start_delay_sec:o.startDelay,measurements:[]};
  try {
    await mkdir(parent,{recursive:true});output=await mkdtemp(path.join(parent,'usb-local-'));
    if(!deps.discoverBoard&&process.platform!=='darwin')throw Error('Local USB runner currently supports macOS only');
    const git=deps.command??command;
    const checkout=await git('git',['rev-parse','HEAD'],{signal});
    const dirty=await git('git',['status','--porcelain'],{signal});
    r.checkout={commit:checkout.code===0?checkout.stdout.trim():null,dirty:dirty.code===0?Boolean(dirty.stdout.trim()):null};
    const board=await (deps.discoverBoard??discoverBoard)(o,signal,log);
    if(board.paths.length!==1||board.paths[0].kind!=='usb')throw Error('USB-only board discovery required');
    const p=board.paths[0];r.path=p;r.transport=p.protocol==='https:'?'HTTPS/TCP (TLS included)':'HTTP/TCP';
    r.board=cleanStatus(board.initial);
    log(`Local USB: ${p.iface}, start delay ${o.startDelay}s; output ${output}`);
    await wait(o.startDelay*1000,signal);
    for(let run=0;run<=o.runs;run++) {
      const m={run,warmup:run===0,started:new Date().toISOString()};r.measurements.push(m);
      try {
        await (deps.checkLocalRoute??checkLocalRoute)(p,signal);
        m.before=cleanStatus(await board.status());
        log(`Local USB ${m.warmup?'warm-up':`${run}/${o.runs}`}: 8 MiB`);
        Object.assign(m,await board.download());
        await (deps.checkLocalRoute??checkLocalRoute)(p,signal);
        await wait(3000,signal);
        m.after=cleanStatus(await board.status());
        m.counters=counterDelta(m.before,m.after);
        if(m.after.uptime_sec<m.before.uptime_sec)throw Error('Board restarted during local test');
      } catch(e) {m.error=e.message;throw e;} // Do not pile requests onto a stalled HTTP worker.
    }
    r.warnings=[];
    for(const m of r.measurements) {
      const c=m.counters;
      if(['full','send_failed','expired','stale','no_host','invalid_length','not_ready','enqueue_failed']
          .some(k=>c?.[`usb.tx_queue.${k}`]>0))r.warnings.push(`run ${m.run}: USB queue rejection/send failure (not TCP application loss)`);
      if(c?.['usb.tx_ok']==null||c?.['usb.ncm.ntb_completed']==null)r.warnings.push(`run ${m.run}: USB/NCM counter window unavailable`);
    }
    r.status=r.warnings.length?'completed-with-warnings':'completed';
  } catch(e) {r.error=signal.aborted?'Interrupted':e.message;}
  finally {
    process.removeListener('SIGINT',stop);process.removeListener('SIGTERM',stop);
    r.ended=new Date().toISOString();r.receiver_mbps=stats(r.measurements.filter(m=>!m.warmup&&!m.error).map(m=>m.receiver_mbps));
    if(output){await writeFile(path.join(output,'result.json'),JSON.stringify(r,null,2));await writeFile(path.join(output,'report.md'),localReport(r));log(`Saved ${output}`);}
  }
  if(r.error)log(r.error);
  return r.status==='completed'?0:r.status==='completed-with-warnings'?2:1;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))main().then(code=>{process.exitCode=code;}).catch(e=>{console.error(e.message);process.exitCode=1;});
