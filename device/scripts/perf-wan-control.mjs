// Small public download control for STA -> USB with VPN disabled. This is WAN
// throughput, including the provider/CDN path; it is not a Wi-Fi or USB ceiling.
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {setTimeout as delay} from 'node:timers/promises';
import assert from 'node:assert/strict';
import {discoverBoard,checkLocalRoute} from './perf-network.mjs';
import {cleanStatus} from './perf-runner.mjs';
import {stats} from './perf-lib.mjs';
const execute=promisify(execFile), bytes=8*1024*1024;
export async function wanControl({out,runs=3,adminURL,board:target=process.env.BOARD||'waveshare'}={}) {
  if(!out||!Number.isInteger(runs)||runs<1||runs>5)throw Error('Require --out NEW_DIRECTORY and runs 1..5');
  await fs.mkdir(path.dirname(path.resolve(out)),{recursive:true});await fs.mkdir(out);
  const r={started:new Date().toISOString(),status:'running',scope:'Public CDN -> STA -> USB, VPN disabled; provider/CDN limits included',measurements:[]};
  const controller=new AbortController(),stop=()=>controller.abort();process.once('SIGINT',stop);process.once('SIGTERM',stop);
  let pending=null;
  try {
    const board=await discoverBoard({paths:'usb',localOnly:false,adminURL,board:target},controller.signal,console.log);
    assert(!board.initial.vpn.enabled);
    r.before=cleanStatus(board.initial);const boot=board.initial.boot_count;
    for(let i=0;i<runs;i++) {
      await checkLocalRoute(board.paths[0],controller.signal);
      const m={run:i,started:new Date().toISOString(),admin_ms:[],samples:[]};r.measurements.push(m);
      let done=false;
      const transfer=pending=execute('/usr/bin/curl',['--noproxy','*','-4','--interface',board.paths[0].iface,
        '--connect-timeout','10','--max-time','90','--max-filesize',String(bytes),'-f','-sS','-o','/dev/null',
        '-w','%{http_code}|%{size_download}|%{speed_download}|%{time_total}',
        `https://speed.cloudflare.com/__down?bytes=${bytes}`],{timeout:95000,signal:controller.signal,maxBuffer:65536})
        .then(v=>({value:v}),error=>({error})).finally(()=>{done=true;});
      while(!done){
        const started=performance.now(),s=await board.status();
        assert.equal(s.boot_count,boot,'P4 rebooted under STA/USB load');assert(s.wifi.connected&&s.usb.host_ready);
        m.admin_ms.push(performance.now()-started);m.samples.push(cleanStatus(s));await delay(500,undefined,{signal:controller.signal});
      }
      const result=await transfer;pending=null;if(result.error)throw result.error;
      const [code,size,speed,seconds]=result.value.stdout.trim().split('|').map(Number);
      assert.equal(code,200);assert.equal(size,bytes);assert(speed>0&&seconds>0);
      Object.assign(m,{bytes:size,seconds,receiver_mbps:size*8/seconds/1e6,curl_body_mbps:speed*8/1e6});
      m.after=cleanStatus(await board.status());
      await fs.appendFile(path.join(out,'measurements.ndjson'),JSON.stringify(m)+'\n');
      console.log(`STA/USB control ${i+1}/${runs}: ${m.receiver_mbps.toFixed(2)} Mbit/s`);await delay(3000);
    }
    r.after=cleanStatus(await board.status());r.status='completed';
  }catch(e){r.status='failed';r.error=e.message;}
  finally {
    controller.abort();if(pending)await pending;
    r.ended=new Date().toISOString();r.receiver_mbps=stats(r.measurements.map(m=>m.receiver_mbps));
    r.admin_latency_ms=stats(r.measurements.flatMap(m=>m.admin_ms));
    await fs.writeFile(path.join(out,'result.json'),JSON.stringify(r,null,2));
    process.removeListener('SIGINT',stop);process.removeListener('SIGTERM',stop);
  }
  return r;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const o={};
  for(let i=2;i<process.argv.length;i++){
    const key={'--board':'board','--admin-url':'adminURL','--out':'out'}[process.argv[i]];
    if(key&&process.argv[i+1])o[key]=process.argv[++i];
    else if(!process.argv[i].startsWith('-')&&!o.out)o.out=process.argv[i];
    else throw Error('Unknown option or missing value');
  }
  const r=await wanControl(o);
  console.log(JSON.stringify({status:r.status,error:r.error,mbps:r.receiver_mbps,admin_ms:r.admin_latency_ms}));
  process.exitCode=r.status==='completed'?0:1;
}
