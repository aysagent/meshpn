#!/usr/bin/env node
import { collectHostPreflight, parseHostPreflightArgs } from './lib/host-preflight.mjs';
try {
  const options = parseHostPreflightArgs(process.argv.slice(2));
  if (options.help) console.log('Usage: sudo node scripts/clean-vpn-host-preflight.mjs --exit-ip=IPv4\nRead-only default-service inventory for host-client autostart review. No probes, installation, stop/start, recovery or reboot. Includes IPs and interface names; no secrets.');
  else {
    if (process.platform !== 'linux') throw Error('Linux required');
    const controller = new AbortController(), abort = () => controller.abort();
    process.on('SIGINT', abort); process.on('SIGTERM', abort);
    let report;
    try {
      console.error('[host-preflight] Только чтение: службы, интерфейсы и предпосылки автозапуска; сеть не меняется');
      report = await collectHostPreflight(options, { signal: controller.signal });
    } finally { process.off('SIGINT', abort); process.off('SIGTERM', abort); }
    console.log('=== CLEAN-VPN HOST PREFLIGHT BEGIN ===');
    console.log(JSON.stringify(report, null, 2));
    console.log('=== CLEAN-VPN HOST PREFLIGHT END ===');
    if (report.status !== 'inventory-ready-for-review') process.exitCode = 1;
  }
} catch { console.error('HOST_PREFLIGHT_FAILED: invalid arguments or inventory error; see --help. No settings changed.'); process.exitCode = 1; }
