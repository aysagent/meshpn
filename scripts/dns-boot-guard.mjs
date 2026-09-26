#!/usr/bin/env node
import assert from 'node:assert/strict';
import { loadDnsBootGuard, attestDnsBootNamespace } from './lib/dns-boot-guard.mjs';

let phase = 'arguments';
try {
  const args = process.argv.slice(2);
  assert.ok(args.length === 1 && ['--start', '--inspect', '--attest-namespace'].includes(args[0]));
  if (args[0] === '--attest-namespace') {
    await attestDnsBootNamespace({ onPhase: (next) => { phase = next; } });
  } else {
  phase = 'authority-policy-tools';
  const { guard } = await loadDnsBootGuard({ onPhase: (next) => { phase = next; } });
  phase = 'firewall';
  const result = args[0] === '--start' ? await guard.ensure() : { states: await guard.inspect(), mode: 'read-only' };
  console.log(JSON.stringify({ ...result, schema: 1, kind: 'clean-vpn-dns-boot-guard', dnsJournalAdopted: false, dnsSettingsChanged: false }));
  }
} catch (error) {
  const code = typeof error.code === 'string' && /^[A-Z0-9_]{1,40}$/.test(error.code) ? error.code : 'FAILED';
  console.error(`DNS_BOOT_GUARD_REFUSED phase=${phase} code=${code}`); process.exitCode = 1;
}
