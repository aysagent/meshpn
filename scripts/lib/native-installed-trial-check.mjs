// Real update+rollback while the existing USB DNS/route owner remains alive.
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {installedTrialName as name} from './native-installed-trial.mjs';
export async function checkInstalledTrial({run,probe,scratch,engine}) {
  const root=fileURLToPath(new URL('../../',import.meta.url)),bundle='/opt/clean-vpn-native/'+name;
  const need=(v,c)=>{if(!v)throw Error(c);},hash=b=>createHash('sha256').update(b).digest('hex');
  const update=(...a)=>run(process.execPath,[root+'scripts/clean-vpn-native-update.mjs',...a],240000);
  const prop=(u,k)=>run('systemctl',['show',u,'-p',k,'--value']);
  const unit='native-'+name+'.service',checks=[];
  const networkPid=await prop('clean-vpn-native-trial.service','MainPID');
  const snat=JSON.parse(await run(process.execPath,[root+'scripts/clean-vpn-usb-snat.mjs','--status','--native-unit='+unit],90000));
  need(snat.status==='ready','native_usb_snat_not_ready');checks.push('native-snat-owner-readiness');
  const attempt=bundle+'/clock-state/attempt.json';need(!fs.existsSync(attempt),'unexpected_clock_query');
  const next=scratch+'/engine-next',bad=scratch+'/engine-bad';
  const before=hash(fs.readFileSync(bundle+'/engine'));
  const state=bundle+'/clock-state/last-good.json';
  need(!fs.existsSync(state),'unexpected_clock_floor');
  // Real trust anchor is verified separately using the copied pin/key; this is
  // a read-only explicit probe, not an automatic boot query or clock change.
  const clock=JSON.parse(await run('/usr/bin/python3',['-I',bundle+'/clock.py','probe','--config='+bundle+'/clock.json'],15000));
  need(clock.status==='passed'&&clock.systemClockChanged===false&&!clock.needsCorrection,'clock_probe_failed');checks.push('pinned-clock-probe');
  try {
    fs.writeFileSync(next,Buffer.concat([fs.readFileSync(engine),Buffer.from('\ninstalled-lifecycle-fixture\n')]),{mode:0o755,flag:'wx'});
    const expected=hash(fs.readFileSync(next));
    need(JSON.parse(await update('--apply',name,next,expected)).status==='updated','installed_update_failed');
    need((await probe()).status==='ipv4-smoke-passed','installed_update_dns_https_failed');checks.push('update-dns-https');
    // Capabilities/config validation succeed, but service exits with the clock
    // error code. Shared update lock must prevent any SSH/clock side effects.
    fs.writeFileSync(bad,`#!/bin/sh\ncase "$1" in --capabilities|--check-config) exec ${bundle}/binary-updates/releases/${expected} "$@";; *) exit 77;; esac\n`,{mode:0o755,flag:'wx'});
    let failed=false;try{await update('--apply',name,bad,hash(fs.readFileSync(bad)));}catch{failed=true;}
    need(failed&&hash(fs.readFileSync(bundle+'/engine'))===expected,'installed_rollback_failed');
    need((await probe()).status==='ipv4-smoke-passed','installed_rollback_dns_https_failed');checks.push('rollback-dns-https');
    need(!fs.existsSync(attempt),'clock_query_during_update');checks.push('no-clock-query-during-update');
    need((await prop('clean-vpn-native-trial.service','MainPID'))===networkPid,'network_owner_restarted');checks.push('network-owner-preserved');
    need(JSON.parse(await update('--apply',name,engine,before)).status==='updated','original_restore_failed');
    need(['ready','idle_wait'].includes(await prop(unit,'StatusText')),'original_not_ready');checks.push('original-binary-restored');
    need(!fs.existsSync(attempt),'healthy_clock_query');checks.push('healthy-no-clock-query');
    return {status:'passed',checks,scope:'temporary-installed-client-existing-DNS-routes-guard',clockChanged:false};
  } finally {for(const file of [next,bad])if(fs.existsSync(file))fs.unlinkSync(file);}
}
