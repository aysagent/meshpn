#!/usr/bin/env node
/** Offline only: no connection, DNS lookup or runtime configuration mutation. */
import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { DNS_UPSTREAM_CONFIG_MAX_BYTES, parseDnsUpstream, dnsUpstreamSummary } from './lib/dns-upstream-config.mjs';

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--help') {
    console.log('Usage: node scripts/dns-upstream-check.mjs --config=/path/to/upstream.json\nOffline contract validation only. No DNS, network, system changes or public resolver selection.\nRegular non-symlink JSON file <=128 KiB; schema described in scripts/dns-upstream-config.md.'); return;
  }
  if (args.length !== 1 || !/^--config=.+$/.test(args[0])) throw new Error('args');
  const file = await open(args[0].slice(9), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = await file.stat();
    if (!info.isFile() || info.size > DNS_UPSTREAM_CONFIG_MAX_BYTES) throw new Error('file');
    const buffer = Buffer.alloc(DNS_UPSTREAM_CONFIG_MAX_BYTES + 1); let size = 0;
    while (size < buffer.length) {
      const { bytesRead } = await file.read(buffer, size, buffer.length - size, null);
      if (!bytesRead) break; size += bytesRead;
    }
    if (size > DNS_UPSTREAM_CONFIG_MAX_BYTES) throw new Error('size');
    const text = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, size));
    console.log(`DNS_UPSTREAM_CONFIG ${JSON.stringify(dnsUpstreamSummary(parseDnsUpstream(text)))}`);
  } finally { await file.close(); }
}
main().catch(() => { console.error('DNS_UPSTREAM_CONFIG_INVALID'); process.exitCode = 1; });
