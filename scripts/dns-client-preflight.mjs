#!/usr/bin/env node
import { parseClientPreflightArgs, collectClientPreflight } from './lib/dns-client-preflight.mjs';

try {
  const options = parseClientPreflightArgs(process.argv.slice(2));
  if (options.help) console.log('Usage: node scripts/dns-client-preflight.mjs --client=vps2|radxa [--probe]\nRead-only support bundle, no installation/setters/service restart. Run on the selected client.\nRoot improves config/process visibility; it does not authorize writes.\n--probe sends real example.com queries through CURRENT settings, possibly direct.\nIncludes filtered dnsmasq argv/config and networkd ownership hints, never raw argv/environment.');
  else {
    if (process.platform !== 'linux') throw new Error('Linux required');
    const report = await collectClientPreflight(options);
    console.log('=== CLEAN-VPN DNS CLIENT PREFLIGHT BEGIN ===');
    console.log(JSON.stringify(report, null, 2));
    console.log('=== CLEAN-VPN DNS CLIENT PREFLIGHT END ===');
  }
} catch {
  // Never print exception payloads: an unavailable file/command may mention credentials.
  console.error('DNS_CLIENT_PREFLIGHT_FAILED: use --help; unsupported arguments, environment or report failure.'); process.exitCode = 1;
}
