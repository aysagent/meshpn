#!/usr/bin/env node
import { collectClientCheck, parseClientCheckArgs } from './lib/client-check.mjs';

try {
  const options = parseClientCheckArgs(process.argv.slice(2));
  if (options.help) console.log('Usage: node scripts/clean-vpn-client-check.mjs [--probe] [--tun=tun0] [--expect-exit-ip=IPv4]\nChecks an ALREADY RUNNING host client. No VPN start/stop, routes, firewall or DNS settings changed.\n--probe sends real DNS/Cloudflare HTTPS requests and requests a 1 MiB download.\nNo credentials collected. Report includes IPs/routes. No live leak-test or kill-switch claim.');
  else {
    if (process.platform !== 'linux') throw Error('Linux required');
    const controller = new AbortController(), abort = () => controller.abort();
    process.on('SIGINT', abort); process.on('SIGTERM', abort);
    let report;
    try { report = await collectClientCheck(options, { signal: controller.signal, onProgress: text => console.error(`[client-check] ${text}`) }); }
    finally { process.off('SIGINT', abort); process.off('SIGTERM', abort); }
    console.log('=== CLEAN-VPN CLIENT CHECK BEGIN ===');
    console.log(JSON.stringify(report, null, 2));
    console.log('=== CLEAN-VPN CLIENT CHECK END ===');
    if (!['inspection-only', 'ipv4-smoke-passed'].includes(report.status)) process.exitCode = 1;
  }
} catch {
  console.error('CLIENT_CHECK_FAILED: invalid options or collection failure; see --help. No settings changed.');
  process.exitCode = 1;
}
