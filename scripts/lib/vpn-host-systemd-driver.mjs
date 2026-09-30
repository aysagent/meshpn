import { mkdtempSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { assertHostSystemdVm } from './vpn-host-systemd-vm.mjs';

assertHostSystemdVm();
try {
  const { runIpv6Lab } = await import('./vpn-ipv6-lab.mjs');
  console.log(JSON.stringify(await runIpv6Lab(mkdtempSync('/tmp/host-systemd-'), { systemd: true })));
  console.log('INGRESS_VM_PASS');
} catch (error) { console.error(error); console.log('INGRESS_VM_FAIL'); }
execFileSync('/bin/poweroff', ['-f']);
