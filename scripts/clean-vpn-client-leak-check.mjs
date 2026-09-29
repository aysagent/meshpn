#!/usr/bin/env node
import { collectLeakCheck, parseLeakCheckArgs } from './lib/client-leak-check.mjs';
try {
  const options = parseLeakCheckArgs(process.argv.slice(2));
  if (options.help) console.log('Usage: node scripts/clean-vpn-client-leak-check.mjs --exit-ip=PUBLIC_IPV4 [--probe] [--tun=tun0]\nAlready running host client only. --probe requires root/tcpdump and intentionally tests possible direct IPv6 egress. No network settings changed.');
  else {
    if (process.platform !== 'linux' || options.probe && process.getuid() !== 0) throw Error('Linux/root required');
    const controller = new AbortController(), abort = () => controller.abort();
    process.on('SIGINT', abort); process.on('SIGTERM', abort);
    let report;
    try { report = await collectLeakCheck(options, { signal: controller.signal, onProgress: t => console.error(`[leak-check] ${t}`) }); }
    finally { process.off('SIGINT', abort); process.off('SIGTERM', abort); }
    console.log('=== CLEAN-VPN CLIENT LEAK CHECK BEGIN ===');
    console.log(JSON.stringify(report, null, 2));
    console.log('=== CLEAN-VPN CLIENT LEAK CHECK END ===');
    if (report.status !== 'inspection-only') process.exitCode = report.status === 'bypass-or-uplink-traffic-observed' ? 2 : 1;
  }
} catch { console.error('LEAK_CHECK_FAILED: check --help, Linux and sudo. No network settings changed.'); process.exitCode = 1; }
