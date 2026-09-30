import { mkdtempSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { assertHostSystemdVm } from './vpn-host-systemd-vm.mjs';

assertHostSystemdVm();
try {
  const { runIpv6Lab } = await import('./vpn-ipv6-lab.mjs');
  const stopFaults = /(?:^|\s)meshpn.host-stop-faults=1(?:\s|$)/.test(readFileSync('/proc/cmdline','utf8'));
  const networkGate = /(?:^|\s)meshpn.host-network-gate=1(?:\s|$)/.test(readFileSync('/proc/cmdline','utf8'));
  const networkd = /(?:^|\s)meshpn.host-networkd=1(?:\s|$)/.test(readFileSync('/proc/cmdline','utf8'));
  const bootOrder = !networkGate && /(?:^|\s)meshpn.host-boot-order=1(?:\s|$)/.test(readFileSync('/proc/cmdline','utf8'));
  console.log(JSON.stringify(await runIpv6Lab(mkdtempSync('/tmp/host-systemd-'), { systemd: true, stopFaults, bootOrder, networkGate, networkd })));
  console.log('INGRESS_VM_PASS');
} catch (error) { console.error(error); console.log('INGRESS_VM_FAIL'); }
execFileSync('/bin/poweroff', ['-f']);
