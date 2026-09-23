/** Explicit exit-only opt-in; call before any VPN/TUN/listener initialization. */
import { readDnsUpstreamConfig } from './dns-upstream-config-file.mjs';
import { dnsUpstreamExitPolicy } from './dns-upstream-config.mjs';

export async function loadExitDnsUpstreamPolicy({ role, type }, argv) {
  const flag = '--tls-dns-upstream-config';
  const matches = argv.filter((arg) => arg.startsWith(flag));
  if (!matches.length) return undefined;
  if (matches.length !== 1 || !matches[0].startsWith(`${flag}=`) || matches[0].length === flag.length + 1
    || role !== 'exit' || !['transparent-tls', 'combo-tls'].includes(type)) {
    throw Object.assign(new Error('DNS_UPSTREAM_CONFIG'), { code: 'DNS_UPSTREAM_CONFIG' });
  }
  return dnsUpstreamExitPolicy(await readDnsUpstreamConfig(matches[0].slice(flag.length + 1)));
}
