#!/usr/bin/env node
import { dnsBootDryRun, DNS_BOOT_SCENARIOS } from './lib/dns-boot.mjs';
const args = process.argv.slice(2);
try {
  if (args.length === 1 && args[0] === '--help') console.log(`Usage: node scripts/dns-boot.mjs [--scenario=${DNS_BOOT_SCENARIOS.join('|')}]\nOffline protocol proposal only. No host reads, --apply or VM launch.`);
  else {
    if (args.length > 1 || (args.length && !/^--scenario=[a-z-]+$/.test(args[0]))) throw new Error('invalid arguments');
    console.log(JSON.stringify(dnsBootDryRun(args[0]?.slice(11)), null, 2));
  }
} catch (error) { console.error(error.message); process.exitCode = 1; }
