// Only the dedicated clock VM. No physical host or shared Podman clock.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
import net from 'node:net';
assert.ok(fs.readFileSync('/proc/cmdline','utf8').split(/\s+/).includes('meshpn.clock-vm=1'));
const role=process.argv[2],phase=Number(process.argv[3]??fs.readFileSync('/proc/cmdline','utf8').match(/meshpn.clock-phase=(\d)/)?.[1]??0);
assert.ok(['exit','client'].includes(role));
const run=(c,a)=>execFileSync(c,a,{encoding:'utf8',timeout:10000,stdio:['ignore','pipe','pipe']}).trim();
const ctl=(...a)=>run('/usr/bin/systemctl',a);
const wait=async(fn,ms=45000)=>{const end=performance.now()+ms;let last;while(performance.now()<end){try{return fn();}catch(e){last=e;await delay(150);}}throw last;};
const read=p=>fs.existsSync(p)?fs.readFileSync(p,'utf8'):'';
const check=(label)=>console.log('CLOCK_VM_STEP='+label);
if(role==='exit'){
  try {
  await wait(()=>assert.equal(ctl('is-active','cvpn-exit.service'),'active'));
  await wait(()=>assert.equal(run('/usr/bin/timedatectl',['show','-p','NTPSynchronized','--value']),'yes'));
  await wait(()=>assert.equal(ctl('is-active','clock-sshd.service'),'active'));
  } catch(error) {
    try { console.log(ctl('status','--no-pager','-l','dbus.socket','dbus.service','systemd-timedated.service','clock-reference.service','clock-sshd.service')); } catch(e) { console.log(String(e.stdout)); }
    console.log(read('/run/sshd.log'));throw error;
  }
  const origin=net.createServer(s=>{s.end('guard bypass');});origin.listen(8443,'192.0.2.2');
  console.log('CLOCK_EXIT_READY');
  let last=-1;
  setInterval(()=>{const count=(read('/run/sshd.log').match(/Starting session: forced-command/g)??[]).length;
    if(count!==last){last=count;console.log('CLOCK_EXIT_SSH_COUNT='+count);}},100);
}else{
  const bootId=read('/proc/sys/kernel/random/boot_id').trim(),steps=[];
  const step=s=>{steps.push(s);check(s);};
  const active=name=>ctl('show',`cvpn-${name}.service`,'-p','ActiveState','--value');
  const log=name=>read(`/run/engine-${name}.log`);
  const recovery=name=>read(`/run/recovery-${name}.log`);
  const stop=name=>ctl('stop',`cvpn-${name}.service`);
  const start=name=>ctl('--no-block','start',`cvpn-${name}.service`);
  const ready=async name=>{await wait(()=>assert.equal(active(name),'active'));
    assert.match(log(name),/"state":"ready"/);
    const pid=ctl('show',`cvpn-${name}.service`,'-p','MainPID','--value');
    assert.match(fs.readlinkSync('/proc/'+pid+'/exe'),/\/engine$/);
    const caps=BigInt('0x'+read('/proc/'+pid+'/status').match(/^CapEff:\s*([a-f0-9]+)$/m)[1]);
    assert.equal(caps&(1n<<25n),0n,'native engine must not have SYS_TIME');
    assert.match(run('/bin/ping',['-c','1','-W','3','10.99.0.1']),/1 packets received|1 received/);
  };
  const blocked=async()=>{
    assert.equal(ctl('is-active','cvpn-guard.service'),'active');
    await new Promise((resolve,reject)=>{const s=net.connect(8443,'192.0.2.2');
      s.setTimeout(500,()=>{s.destroy();resolve();});s.on('error',()=>resolve());s.on('connect',()=>{s.destroy();reject(Error('guard_bypass'));});});
  };
  let success=false;
  try{
    await ready('main');await blocked();
    const saved=JSON.parse(read('/state/clock-main/attempt.json'));
    if(phase===1){
      assert.notEqual(saved.boot_id,bootId);assert.equal(recovery('main'),'');
      assert.doesNotMatch(log('main'),/tls_verify_not_yet_valid|tls_verify_expired|auth_clock_skew/);
      step('correct-cold-boot-no-recovery');
    }else{
      assert.equal(saved.boot_id,bootId);assert.equal(saved.failure,'tls_verify_not_yet_valid');
      assert.match(log('main'),/"state":"tls_verify_not_yet_valid"/);
      assert.match(recovery('main'),/"systemClockChanged": true/);
      assert.match(recovery('main'),/"restartQueued": true/);
      assert.ok(Date.now()>Date.UTC(2026,0,1));step('bad-cold-boot-real-ssh-time-set-native-restart');
    }
    const baseline=Date.now(),mono=performance.now();
    const restore=()=>run('/usr/bin/date',['--utc','--set=@'+Math.floor((baseline+performance.now()-mono)/1000)]);
    if(phase===0){
      const prior=recovery('main');stop('main');start('main');await ready('main');
      assert.equal(recovery('main'),prior);step('healthy-service-restart-no-clock-query');stop('main');
      for(const [name,pattern] of [['wrongkey',/"state":"tls_read"|"state":"tls_peer_closed"|"state":"h2_peer_end_stream"|"state":"h2_stream_closed"/],['wrongname',/"state":"tls_verify_name"/],['untrusted',/"state":"tls_verify_untrusted"/],['timeout',/"state":"connect_deadline"/]]){
        start(name);await wait(()=>assert.match(log(name),pattern));
        assert.doesNotMatch(log(name),/"state":"ready"/);assert.equal(recovery(name),'');
        stop(name);await blocked();step(name+'-does-not-trigger-clock');
      }
      start('expired');await wait(()=>assert.match(recovery('expired'),/"systemClockChanged": false/));
      assert.equal(active('expired'),'failed');assert.doesNotMatch(log('expired'),/"state":"ready"/);
      assert.match(recovery('expired'),/"restartQueued": false/);await blocked();
      step('truly-expired-cert-not-repaired-by-time-rollback');
      start('expired');await wait(()=>assert.match(recovery('expired'),/clock_attempt_already_consumed/));
      assert.equal(active('expired'),'failed');step('failed-service-restart-does-not-reset-attempt-budget');
      run('/usr/bin/date',['--utc','--set=@1483228800']);
      start('wrongpin');await wait(()=>assert.match(recovery('wrongpin'),/authenticated_clock_query_failed/));
      assert.ok(Date.now()<Date.UTC(2018,0,1));assert.equal(active('wrongpin'),'failed');await blocked();
      step('wrong-ssh-host-key-blocks-time-set-and-restart');restore();
      run('/usr/bin/date',['--utc','--set=@'+Math.floor((baseline+performance.now()-mono-13*3600000)/1000)]);
      start('skew');await ready('skew');assert.match(log('skew'),/"state":"auth_clock_skew"/);
      assert.match(recovery('skew'),/"failure": "auth_clock_skew"/);
      assert.match(recovery('skew'),/"systemClockChanged": true/);step('real-independent-exit-rejects-hmac-skew-then-recovers');stop('skew');
      start('main');await ready('main');assert.equal(recovery('main'),prior);step('normal-vpn-after-all-faults');
    }
    stop('main');await blocked();step('guard-survives-service-stop');
    success=true;
    console.log('CLOCK_VM_REPORT='+JSON.stringify({schema:1,status:'passed',kind:'native-clock-lifecycle-vm',phase,bootId,steps,
      mainAttempt:JSON.parse(read('/state/clock-main/attempt.json')),nativeMainPid:true,engineCanSetTime:false}));
  }finally{
    if(!success)for(const name of ['main','expired','skew','wrongpin','wrongkey','wrongname','untrusted','timeout']){
      console.log('CLOCK_FAILURE_LOG='+name+'\n'+log(name)+'\n'+recovery(name));
    }
  }
}
