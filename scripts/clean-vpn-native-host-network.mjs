#!/usr/bin/env node
// Persistent control plane for the reviewed Radxa profile. No packet/DNS IO.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import {openHostRoutes} from './lib/vpn-host-routes.mjs';
import {openTunnelDnsJournal} from './lib/dns-tunnel-journal.mjs';
import {nativeHostNetwork,validateNativeHostConfig} from './lib/native-host-network.mjs';
import {openNativeHostStore,nativeHostScope,readNativePrivate} from './lib/native-host-store.mjs';

let store,host,dns,timer;
try{
  const [action,flag,...extra]=process.argv.slice(2);
  assert.ok(['run','recover','preflight'].includes(action)&&!extra.length&&/^--config=\/[\w./-]+$/.test(flag));
  const config=validateNativeHostConfig(readNativePrivate(flag.slice(9)));
  assert.equal(process.platform,'linux');assert.equal(process.getuid(),0);
  const st=fs.statSync(config.guard_script);assert.ok(st.isFile()&&st.uid===0&&!(st.mode&0o022));
  store=openNativeHostStore();
  const run=(f,a)=>execFileSync(f,a,{encoding:'utf8',timeout:15000,killSignal:'SIGKILL',maxBuffer:1024*1024,
    env:{PATH:'/usr/sbin:/usr/bin:/sbin:/bin',LC_ALL:'C'},stdio:['ignore','pipe','pipe',store.lock]}).trim();
  const prop=(u,k)=>run('systemctl',['show',u,'-p',k,'--value']);
  if(action==='run')assert.equal(prop(config.network_unit,'MainPID'),String(process.pid),'native_named_owner_required');
  host=openHostRoutes({allowTunLinkDown:true});dns=openTunnelDnsJournal();
  const owner=nativeHostNetwork(config,{run,host,dns,store,scope:nativeHostScope,randomId:()=>randomBytes(12).toString('hex'),
    createTun:(name,alias,peer)=>run('python3',[fileURLToPath(new URL('./clean-vpn-native-tun.py',import.meta.url)),name,alias,peer])});
  if(action==='preflight'){owner.preflight();console.log(JSON.stringify({status:'eligible',networkChanged:false,profile:'radxa-ipv4'}));}
  else if(action==='recover'){
    // BindsTo/After stop the engine before this ExecStopPost. Wait only for
    // completion, never submit a blocking systemd job from its dependency.
    const end=performance.now()+20000;
    while(prop(config.engine_unit,'MainPID')!=='0'&&performance.now()<end)await delay(100);
    owner.recover();console.log(JSON.stringify({status:'recovered',guardReleased:false}));
  }else{
    owner.recover();console.log(JSON.stringify(owner.prepare()));
    assert.equal(prop(config.network_unit,'ActiveState'),'active','native_owner_stopping');
    run('systemctl',['start','--job-mode=fail','--no-block',config.engine_unit]);
    await new Promise((resolve,reject)=>{
      const stop=()=>{clearInterval(timer);resolve();};process.once('SIGTERM',stop);process.once('SIGINT',stop);
      timer=setInterval(()=>{try{owner.tick();}catch(e){clearInterval(timer);reject(e);}},5000);
    });
    // Independent ExecStopPost owns cleanup on both graceful and abrupt exit.
  }
}catch(e){const reason=e.message?.split('\n')[0];console.error('native-host-network: '+(/^native_[a-z0-9_]+$/.test(reason)?reason:e.code??'failed'));process.exitCode=1;}
finally{clearInterval(timer);dns?.release();host?.release();store?.close();}
