// Real systemd/SSH recovery gate. CAP_SYS_TIME is deliberately absent: this
// test must never change the Podman VM's shared kernel clock.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {nativeClockRecoveryUnit} from './lib/native-clock-unit.mjs';
assert.equal(process.env.CVPN_DISPOSABLE_SETUP,'1');
assert.equal(fs.readFileSync('/run/systemd/container','utf8').trim(),'podman');
const run=(f,a)=>execFileSync(f,a,{encoding:'utf8',timeout:30000,stdio:['ignore','pipe','pipe']}).trim();
const ctl=(...a)=>run('systemctl',a),dir='/opt/clean-vpn-clock-test',consumer='native-clock-test-consumer.service',recovery='native-clock-test-recovery.service';
fs.mkdirSync(dir,{mode:0o700});fs.mkdirSync(dir+'/state',{mode:0o700});
const c=JSON.parse(fs.readFileSync('/opt/clean-vpn-native/client/clock.json','utf8'));
c.consumer_unit=consumer;c.state_dir=dir+'/state';delete c.update_directory;
fs.writeFileSync(dir+'/config.json',JSON.stringify(c),{mode:0o600});
fs.writeFileSync('/etc/systemd/system/'+consumer,'[Service]\nType=oneshot\nExecStart=/bin/sh -c "exit 75"\n');
const unit=nativeClockRecoveryUnit({consumerUnit:consumer,script:'/opt/clean-vpn-native/client/clock.mjs',node:'/opt/clean-vpn-native/client/clock-node',config:dir+'/config.json',stateDirectory:dir+'/state'}).replace('CapabilityBoundingSet=CAP_SYS_TIME','CapabilityBoundingSet=');
fs.writeFileSync('/etc/systemd/system/'+recovery,unit);
try{
 ctl('daemon-reload');assert.throws(()=>ctl('start',consumer));ctl('start',recovery);
 const logs=run('journalctl',['-u',recovery,'-o','cat','--no-pager']);
 const result=logs.split('\n').filter(l=>l.startsWith('{')).map(l=>JSON.parse(l)).find(r=>r.status==='passed');
 assert.ok(result,logs);assert.equal(result.systemClockChanged,false);assert.equal(result.restartQueued,false);assert.equal(result.failure,'tls_verify_not_yet_valid');
 assert.ok(fs.existsSync(dir+'/state/last-good.json'));
 assert.throws(()=>ctl('start',recovery));
 assert.match(run('journalctl',['-u',recovery,'-o','cat','--no-pager']),/clock_attempt_already_consumed/);
 console.log('CLOCK_SYSTEMD_SANDBOX_FAILURE_GATE_AND_BOOT_BUDGET_OK_NO_TIME_CAPABILITY');
}finally{
 for(const u of [consumer,recovery]){try{ctl('stop',u);}catch{}fs.unlinkSync('/etc/systemd/system/'+u);}
 ctl('daemon-reload');
}
