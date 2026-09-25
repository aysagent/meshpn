#!/usr/bin/env node
import { collectDnsDiagnostic, parseDiagnosticArgs } from './lib/dns-diagnostic.mjs';

try {
  const options = parseDiagnosticArgs(process.argv.slice(2));
  if (options.help) {
    console.log('Usage: node scripts/dns-diagnostic.mjs [--probe]\nLinux support report to stdout; no settings changed, no root required.\n--probe: real example.com DNS queries through CURRENT settings (possibly direct).\nReport includes IPs/domains, not credentials. Missing tools are reported; nothing is installed.');
  } else {
    if (process.platform !== 'linux') throw new Error('Linux required');
    console.log('=== CLEAN-VPN DNS DIAGNOSTIC BEGIN ===');
    console.log(JSON.stringify(await collectDnsDiagnostic(options), null, 2));
    console.log('=== CLEAN-VPN DNS DIAGNOSTIC END ===');
  }
} catch (error) {
  console.error(`DNS_DIAGNOSTIC_FAILED: ${error.message}`); process.exitCode = 1;
}
