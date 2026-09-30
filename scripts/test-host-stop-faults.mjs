import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { HOST_SYSTEMD_CHECKS, HOST_STOP_FAULT_CHECKS, assertHostSystemdEvidence } from './lib/vpn-host-systemd-vm.mjs';
import { hostStopFaultShim, runHostStopFaultChecks } from './lib/vpn-host-stop-faults-lab.mjs';

test('stop fault driver refuses the development host before any fixture mutation',async()=>{
  await assert.rejects(runHostStopFaultChecks({}),/meshpn\.host-systemd/);
});
test('fault shim is syntactically valid, cgroup scoped and arms only on explicit marker',()=>{
  const s=hostStopFaultShim(),p=spawnSync('/bin/bash',['-n'],{input:s,encoding:'utf8',timeout:5000});
  assert.equal(p.status,0,p.stderr);
  assert.match(s,/\/proc\/self\/cgroup/);assert.match(s,/\/clean-vpn\.service/);
  assert.match(s,/\/run\/host-stop-fault\.mode/);assert.match(s,/-w 5 -t filter -S/);
  assert.match(s,/exec \/usr\/sbin\/xtables-legacy-multi iptables "\$@"/);
  assert.match(s,/exit 77/);assert.match(s,/exec \/bin\/sleep 600/);
});
test('fault evidence is distinct from successful lifecycle evidence and cannot omit checks',()=>{
  const e={status:'passed',actualTransportTested:'tls-ipv6',hostNetworkChanged:false,checks:[...HOST_STOP_FAULT_CHECKS],
    hostSystemd:{systemdPid1:true,actualInstaller:true,stopFaults:true,acceleratedStopTimeoutSec:5,acceptance:'not-ready-for-deployment',
      limitations:['fixture-network-namespace-dropins','no-early-boot-or-reboot','explicit-recovery-not-auto-restart']}};
  assertHostSystemdEvidence(e,{stopFaults:true});
  assert.throws(()=>assertHostSystemdEvidence(e));
  assert.throws(()=>assertHostSystemdEvidence({...e,checks:[...HOST_SYSTEMD_CHECKS]},{stopFaults:true}));
  for(let i=0;i<e.checks.length;i++)assert.throws(()=>assertHostSystemdEvidence({...e,checks:e.checks.filter((_,j)=>i!==j)},{stopFaults:true}));
  for(const acceleratedStopTimeoutSec of [undefined,420,0])assert.throws(()=>assertHostSystemdEvidence({...e,
    hostSystemd:{...e.hostSystemd,acceleratedStopTimeoutSec}},{stopFaults:true}));
});
test('stop fault CLI refuses missing systemd selection before artifact creation',()=>{
  const p=spawnSync(process.execPath,['scripts/ingress-vm-lab.mjs','--tools=/not-used','--kernel=/not-used',
    '--resolved=/not-used','--host-stop-faults'],{encoding:'utf8',timeout:5000});
  assert.equal(p.status,1);assert.match(p.stderr,/--host-stop-faults requires --host-systemd/);
  assert.doesNotMatch(p.stderr,/Ingress VM artifacts/);
});
test('production timeout stays unchanged; shortened timeout only exists behind VM assertion',()=>{
  const installed=readFileSync(new URL('./autostart/install.sh',import.meta.url),'utf8');
  assert.match(installed,/^TimeoutStopSec=420$/m);assert.doesNotMatch(installed,/host-stop-fault/);
  const source=readFileSync(new URL('./lib/vpn-host-stop-faults-lab.mjs',import.meta.url),'utf8');
  assert.ok(source.indexOf('assertHostSystemdVm();')<source.indexOf('unlinkSync(shim)'));
  assert.match(source,/TimeoutStopSec=5s/);assert.match(source,/unlinkSync\(override\)/);
});
