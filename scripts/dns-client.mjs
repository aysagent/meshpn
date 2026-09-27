#!/usr/bin/env node
/** Installed DNS controller entrypoint. Inspection only until OS factories and
 * activation/rollback integration are verified. No live mutation commands. */
import { fileURLToPath } from 'node:url';
import { loadDnsInstalledAuthority, assertDnsInstalledAuthority, dnsInstalledAuthorityInfo } from './lib/dns-installed-authority.mjs';
import { inspectInstalledVps2Dns } from './lib/dns-installed-vps2.mjs';

export function parseDnsClientArgs(argv) {
  if (argv.length === 1 && ['--help', '--inspect'].includes(argv[0])) return argv[0].slice(2);
  throw Object.assign(new Error('DNS_CLIENT_ARGUMENTS'), { code: 'DNS_CLIENT_ARGUMENTS' });
}
async function main() {
  const command = parseDnsClientArgs(process.argv.slice(2));
  if (command === 'help') {
    console.log('Usage: node scripts/dns-client.mjs --inspect | --help\nRead-only installed authority inspection; no DNS switch or installer.'); return;
  }
  const token = await loadDnsInstalledAuthority(), info = dnsInstalledAuthorityInfo(token);
  const baseline = info.client === 'vps2' ? await inspectInstalledVps2Dns(token) : null;
  await assertDnsInstalledAuthority(token);
  console.log(JSON.stringify({ schema: 1, kind: 'clean-vpn-dns-client-inspection', mode: 'read-only', client: info.client,
    installedAuthorityVerified: true, dnsOwnershipVerified: false, systemSettingsChanged: false, dnsQueriesSent: 0,
    baseline, limitations: ['not-an-installer', 'no-mutation-ownership-authority', 'no-live-activation-or-rollback', 'not-a-readiness-or-leak-test'] }));
}
if (process.argv[1] === fileURLToPath(import.meta.url)) main().catch((e) => {
  console.error(e.code === 'DNS_CLIENT_ARGUMENTS' ? 'DNS_CLIENT_ARGUMENTS' : 'DNS_CLIENT_REFUSED'); process.exitCode = 1;
});
