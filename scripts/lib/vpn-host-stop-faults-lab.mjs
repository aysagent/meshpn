/** Destructive fault injection exclusively inside the marked NIC-less VM.
 * The shim is armed only after a healthy connection and only affects helpers
 * in the main VPN service cgroup. Driver/recovery/guard commands pass through.
 */
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, readlinkSync, unlinkSync, existsSync, cpSync, mkdirSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';
import { assertHostSystemdVm } from './vpn-host-systemd-vm.mjs';

export const hostStopFaultShim = () => `#!/bin/bash
set -eu
mode=''
if [[ -f /run/host-stop-fault.mode && "$*" == '-w 5 -t filter -S' ]]; then
  while IFS= read -r line; do
    if [[ "$line" == *'/clean-vpn.service' ]]; then read -r mode < /run/host-stop-fault.mode; fi
  done < /proc/self/cgroup
fi
if [[ "$mode" == error || "$mode" == timeout ]]; then
  printf '%s %s %s\\n' "$mode" "$$" "$PPID" > /run/host-stop-fault.hit
  echo "HOST_STOP_FAULT $mode" >&2
  if [[ "$mode" == error ]]; then exit 77; fi
  exec /bin/sleep 600
fi
exec /usr/sbin/xtables-legacy-multi iptables "$@"
`;

export async function runHostStopFaultChecks({ check, query, dns, recover, ready, logs, property, ctl, exec, snapshot, baseline, fileContents }) {
  assertHostSystemdVm();
  assert.match(readFileSync('/proc/cmdline','utf8'), /(?:^|\s)meshpn.host-stop-faults=1(?:\s|$)/);
  const main='clean-vpn.service', guard='clean-vpn-killswitch.service';
  const shim='/usr/sbin/iptables', fault='/run/host-stop-fault.mode', hit='/run/host-stop-fault.hit';
  const override='/etc/systemd/system/clean-vpn.service.d/stop-fault.conf';
  const release='/opt/clean-vpn-stop-fault-release';
  mkdirSync('/opt',{recursive:true}); cpSync('/project',release,{recursive:true});
  assert.equal(readlinkSync(shim),'/usr/sbin/xtables-legacy-multi');
  // Only the validated disposable VM alias is replaced, never host iptables.
  unlinkSync(shim); writeFileSync(shim,hostStopFaultShim(),{mode:0o755,flag:'wx'});
  const originalFiles=fileContents();
  const recoverScripts=['clean-vpn-dns-recover.mjs','clean-vpn-ipv6-recover.mjs','clean-vpn-host-recover.mjs'];
  for (const phase of ['error','timeout']) {
    const offset=logs().length, pid=await property(main,'MainPID'); assert.notEqual(pid,'0');
    if (phase==='timeout') {
      // Accelerate the same KillMode=mixed deadline path; do not spend 420s or
      // change the production unit. The helper command timeout is longer (10s).
      writeFileSync(override,'[Service]\nTimeoutStopSec=5s\n'); await ctl('daemon-reload');
      assert.equal(await property(main,'TimeoutStopUSec'),'5s');
    }
    if(existsSync(hit))unlinkSync(hit);
    writeFileSync(fault,`${phase}\n`);
    let stopError;
    try { await ctl('stop',main); } catch(error) { stopError=error; }
    // Stop job status alone is not proof: inspect actual main result and the
    // injected child identity before any recovery/management can reset it.
    const proof=existsSync(hit)?readFileSync(hit,'utf8').trim().split(' '):[];
    check(`${phase} stop fault reached DNS cleanup`,proof[0]===phase&&proof[2]===pid,true);
    check(`${phase} stop systemd result`,await property(main,'Result'),phase==='error'?'exit-code':'timeout');
    check(`${phase} stop main exit status`,await property(main,'ExecMainStatus'),phase==='error'?'1':'9');
    const reapedBy=Date.now()+5000;
    while(existsSync(`/proc/${proof[1]}`)&&Date.now()<reapedBy)await delay(50);
    check(`${phase} stop detached helper gone`,existsSync(`/proc/${proof[1]}`),false);
    assert.ok(!stopError || /exit|fail|stop|timed/i.test(stopError.message));
    unlinkSync(fault);
    if(phase==='timeout'){unlinkSync(override);await ctl('daemon-reload');}
    check(`${phase} stop guard active`,await property(guard,'ActiveState'),'active');
    for(const [i,label] of ['DNS','IPv6','host'].entries())
      check(`${phase} stop ${label} journal retained`,['active','restoring','installing','parked'].includes((await recover(recoverScripts[i])).stage),true);
    check(`${phase} stop blocks IPv4`,await query('1.0.0.1'),'BLOCKED');
    check(`${phase} stop blocks IPv6`,await query('2606:4700:4700::1111'),'BLOCKED');
    check(`${phase} stop blocks DNS`,await dns(),'BLOCKED');
    const refusedOffset=logs().length; await ctl('start',main);
    const end=Date.now()+60000;
    while(!/recovery required/.test(logs().slice(refusedOffset))){assert.ok(Date.now()<end,logs().slice(offset));await delay(250);}
    await ctl('stop',main);
    check(`${phase} stop restart refuses unfinished journals`,/recovery required/.test(logs().slice(refusedOffset)),true);
    for(const [label,args] of [
      ['updater',['/usr/bin/node','scripts/clean-vpn-update.mjs',`--release=${release}`]],
      ['uninstall',['/bin/bash','scripts/autostart/uninstall.sh']],
    ]){
      let refused;try{await exec('ip',['netns','exec','client',...args]);}catch(error){refused=error;}
      check(`${phase} stop ${label} refuses unfinished journals`,!!refused&&/unfinished VPN journal/.test(refused.stderr),true);
    }
    check(`${phase} stop installed files unchanged`,fileContents(),originalFiles);
    for(const script of recoverScripts)await recover(script,true);
    check(`${phase} stop recovery restores routes`,snapshot(),baseline);
    check(`${phase} stop recovery retains guard`,await property(guard,'ActiveState'),'active');
    const restored=logs().length;await ctl('start',main);await ready(restored);
    check(`${phase} stop restart after recovery`,await query('1.0.0.1'),'198.51.100.2');
  }
  check('fault fixture restored production timeout',await property(main,'TimeoutStopUSec'),'7min');
  await ctl('stop',main);
  await exec('ip',['netns','exec','client','/bin/bash','scripts/autostart/uninstall.sh']);
  check('fault lab clean uninstall restores IPv4',await query('1.0.0.1'),'192.0.2.2');
  check('fault lab clean uninstall restores IPv6',await query('2606:4700:4700::1111'),'2001:db8:1::2');
  check('fault lab clean uninstall restores DNS',await dns(),'192.0.2.10');
  return {systemdPid1:true,actualInstaller:true,stopFaults:true,acceleratedStopTimeoutSec:5,acceptance:'not-ready-for-deployment',limitations:[
    'fixture-network-namespace-dropins','fixture-cgroup-scoped-iptables-shim','accelerated-5s-stop-deadline-not-420s-expiry',
    'persist-mode-only','no-early-boot-or-reboot','explicit-recovery-not-auto-restart','iptables-legacy-only','H2-only-systemd-cycle',
    'no-power-loss-durability-test','no-concurrent-installer-test','no-crash-during-uninstall-test',
  ]};
}
