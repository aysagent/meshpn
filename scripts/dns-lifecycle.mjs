#!/usr/bin/env node
/** Offline only: no host reads, subprocesses or mutation. */
import { dnsLifecycleDryRun, DNS_SCENARIOS } from './lib/dns-lifecycle.mjs';

const args = process.argv.slice(2);
if (args.length === 1 && args[0] === '--help') {
  console.log(`Usage: node scripts/dns-lifecycle.mjs [--scenario=${Object.keys(DNS_SCENARIOS).join('|')}]\nOffline lifecycle proposal only. No --apply, host inspection or system DNS changes. See scripts/dns-lifecycle.md.`);
} else {
  try {
    if (args.length > 1 || (args.length && !/^--scenario=[a-z-]+$/.test(args[0]))) throw new Error('invalid arguments');
    console.log(JSON.stringify(dnsLifecycleDryRun(args[0]?.slice(11)), null, 2));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
