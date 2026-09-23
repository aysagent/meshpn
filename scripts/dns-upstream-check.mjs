#!/usr/bin/env node
/** Offline only: no connection, DNS lookup or runtime configuration mutation. */
import { dnsUpstreamSummary } from './lib/dns-upstream-config.mjs';
import { readDnsUpstreamConfig } from './lib/dns-upstream-config-file.mjs';

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--help') {
    console.log('Usage: node scripts/dns-upstream-check.mjs --config=/path/to/upstream.json\nOffline contract validation only. No DNS, network, system changes or public resolver selection.\nRegular non-symlink JSON file <=128 KiB; schema described in scripts/dns-upstream-config.md.'); return;
  }
  if (args.length !== 1 || !/^--config=.+$/.test(args[0])) throw new Error('args');
  console.log(`DNS_UPSTREAM_CONFIG ${JSON.stringify(dnsUpstreamSummary(await readDnsUpstreamConfig(args[0].slice(9))))}`);
}
main().catch(() => { console.error('DNS_UPSTREAM_CONFIG_INVALID'); process.exitCode = 1; });
