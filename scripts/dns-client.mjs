#!/usr/bin/env node
/** Installed DNS controller entrypoint. Inspection and explicit protected
 * probes only until activation/rollback is verified. No settings mutations. */
import { fileURLToPath } from 'node:url';
import { loadDnsInstalledAuthority, assertDnsInstalledAuthority, dnsInstalledAuthorityInfo } from './lib/dns-installed-authority.mjs';
import { inspectInstalledVps2Dns } from './lib/dns-installed-vps2.mjs';
import { inspectInstalledDnsAdapter, probeInstalledDnsAdapter } from './lib/dns-installed-adapter.mjs';

export function parseDnsClientArgs(argv) {
  if (argv.length === 1 && ['--help', '--inspect', '--inspect-adapter', '--probe-adapter'].includes(argv[0])) return argv[0].slice(2);
  throw Object.assign(new Error('DNS_CLIENT_ARGUMENTS'), { code: 'DNS_CLIENT_ARGUMENTS' });
}
// Fixed code + source location only: no assertion message, values, paths or raw
// stack. Useful for diagnosing refused installs without exposing configuration.
export function dnsClientFailureLocation(error) {
  if (!(error instanceof Error) || typeof error.stack !== 'string') return null;
  const allowed = new Set(['dns-installed-authority.mjs', 'dns-installed-vps2.mjs', 'dns-vps2-baseline.mjs',
    'dns-system-bus.mjs', 'dns-system-command.mjs', 'dns-boot-guard.mjs', 'dns-installed-adapter.mjs']);
  for (const line of error.stack.split('\n').slice(1, 20)) {
    const match = /\bfile:\/\/\/opt\/clean-vpn\/scripts\/lib\/([a-z0-9-]+\.mjs):(\d{1,6}):\d{1,6}\)?$/.exec(line);
    if (match && allowed.has(match[1])) return `${match[1]}:${match[2]}`;
  }
  return null;
}
async function main() {
  const command = parseDnsClientArgs(process.argv.slice(2));
  if (command === 'help') {
    console.log('Usage: node scripts/dns-client.mjs --inspect | --inspect-adapter | --probe-adapter | --help\nInspection changes no settings. --probe-adapter sends four protected DNS queries only with a verified guard and installed adapter. No DNS switch or installer.'); return;
  }
  const token = await loadDnsInstalledAuthority(), info = dnsInstalledAuthorityInfo(token);
  if (command === 'inspect-adapter') {
    console.log(JSON.stringify(await inspectInstalledDnsAdapter(token))); return;
  }
  if (command === 'probe-adapter') {
    console.log(JSON.stringify(await probeInstalledDnsAdapter(token))); return;
  }
  const baseline = info.client === 'vps2' ? await inspectInstalledVps2Dns(token) : null;
  await assertDnsInstalledAuthority(token);
  console.log(JSON.stringify({ schema: 1, kind: 'clean-vpn-dns-client-inspection', mode: 'read-only', client: info.client,
    installedAuthorityVerified: true, dnsOwnershipVerified: false, systemSettingsChanged: false, dnsQueriesSent: 0,
    baseline, limitations: ['not-an-installer', 'no-mutation-ownership-authority', 'no-live-activation-or-rollback', 'not-a-readiness-or-leak-test'] }));
}
if (process.argv[1] === fileURLToPath(import.meta.url)) main().catch((e) => {
  console.error(e.code === 'DNS_CLIENT_ARGUMENTS' ? 'DNS_CLIENT_ARGUMENTS' : 'DNS_CLIENT_REFUSED');
  const location = dnsClientFailureLocation(e); if (location) console.error(`DNS_CLIENT_LOCATION=${location}`);
  process.exitCode = 1;
});
