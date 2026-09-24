#!/usr/bin/env node
import { inspectSystemDns } from './lib/dns-inspect.mjs';

const args = process.argv.slice(2);
if (args.length === 1 && args[0] === '--help') {
  console.log('Usage: node scripts/dns-inspect.mjs\nRead-only Linux DNS evidence. No DNS queries, writes, root requirement or backend selection. Emits redacted JSON; run on the actual VPN client. See scripts/dns-inspect.md.');
} else if (args.length || process.platform !== 'linux') {
  console.error('DNS_INSPECT_INVALID: Linux and no arguments required'); process.exitCode = 1;
} else {
  try { console.log(JSON.stringify(await inspectSystemDns(), null, 2)); }
  catch { console.error('DNS_INSPECT_FAILED'); process.exitCode = 1; }
}
