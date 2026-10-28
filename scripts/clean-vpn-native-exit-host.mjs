#!/usr/bin/env node
// Existing-host exit control plane. C++ owns all packet/TLS IO.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import {openNativeHostStore,nativeHostScope,readNativePrivate} from './lib/native-host-store.mjs';
import {nativeExitHostNetwork,validateNativeExitHost} from './lib/native-exit-host-network.mjs';
let store,timer;
try{
  const [action,flag,...extra]=process.argv.slice(2);
  assert.ok(['run','recover','preflight'].includes(action)&&!extra.length&&/^--config=\/[\w./-]+$/.test(flag));
  const config=validateNativeExitHost(readNativePrivate(flag.slice(9)));
  assert.equal(process.platform,'linux');assert.equal(process.getuid(),0);
  assert.equal(fs.readFileSync('/proc/1/comm','utf8').trim(),'systemd');
  store=openNativeHostStore({kind:'exit'});
  const run=(f,a)=>execFileSync(f,a,{encoding:'utf8',timeout:15000,killSignal:'SIGKILL',maxBuffer:1024*1024,
    env:{PATH:'/usr/sbin:/usr/bin:/sbin:/bin',LC_ALL:'C'},stdio:['ignore','pipe','pipe',store.lock]}).trim();
  const prop=(u,k)=>run('systemctl',['show',u,'-p',k,'--value']);
  if(action==='run')assert.equal(prop(config.network_unit,'MainPID'),String(process.pid),'native_named_owner_required');
  const owner=nativeExitHostNetwork(config,{run,store,scope:nativeHostScope,randomId:()=>randomBytes(12).toString('hex'),
    createTun:(name,alias)=>run('python3',[fileURLToPath(new URL('./clean-vpn-native-tun.py',import.meta.url)),name,alias])});
  if(action==='preflight'){owner.preflight();console.log(JSON.stringify({status:'eligible',networkChanged:false,profile:'existing-exit-ipv4'}));}
  else if(action==='recover'){
    const end=performance.now()+20000;
    while(prop(config.engine_unit,'MainPID')!=='0'&&performance.now()<end)await delay(100);
    owner.recover();console.log(JSON.stringify({status:'recovered',hostForwardingChanged:false}));
  }else{
    owner.recover();console.log(JSON.stringify(owner.prepare()));
    assert.equal(prop(config.network_unit,'ActiveState'),'active','native_owner_stopping');
    run('systemctl',['start','--job-mode=fail','--no-block',config.engine_unit]);
    await new Promise((resolve,reject)=>{
      const stop=()=>{clearInterval(timer);resolve();};process.once('SIGTERM',stop);process.once('SIGINT',stop);
      timer=setInterval(()=>{try{owner.tick();}catch(e){clearInterval(timer);reject(e);}},5000);
    });
  }
}catch(e){const reason=e.message?.split('\n')[0];console.error('native-exit-host: '+(/^native_[a-z0-9_]+$/.test(reason)?reason:e.code??'failed'));process.exitCode=1;}
finally{clearInterval(timer);store?.close();}
