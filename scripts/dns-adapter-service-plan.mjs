#!/usr/bin/env node
/** Prints a reviewed-input plan; never writes deployment files or calls systemctl. */
import { readDnsAdapterServicePlan } from './lib/dns-adapter-service-plan.mjs';

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--help') {
    console.log('Usage: node scripts/dns-adapter-service-plan.mjs --config=/path/service-input.json\nOffline JSON plan only. No installation, DNS queries, credentials read, service or system changes. See scripts/dns-adapter-service-plan.md.'); return;
  }
  if (args.length !== 1 || !/^--config=.+$/.test(args[0])) throw new Error();
  console.log(JSON.stringify(await readDnsAdapterServicePlan(args[0].slice(9)), null, 2));
}
main().catch(() => { console.error('DNS_SERVICE_PLAN_INVALID'); process.exitCode = 1; });
