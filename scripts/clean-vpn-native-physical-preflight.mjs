#!/usr/bin/env node
import { collectNativePhysicalPreflight, parseNativePhysicalPreflightArgs } from './lib/native-physical-preflight.mjs';

try {
  const options = parseNativePhysicalPreflightArgs(process.argv.slice(2));
  if (options.help) {
    console.log('Usage: sudo node scripts/clean-vpn-native-physical-preflight.mjs --role=client|exit --name=INSTANCE --binary=/absolute/clean-vpn-engine --config=/absolute/combo.json --site-profile=/absolute/site.json\nRead-only physical combo inventory and exact offline plan. No probes, TUN/firewall/systemd changes, install, start, stop or reboot. Output contains IPs, paths and unit contents, but no key bytes or raw config.');
  } else {
    if (process.platform !== 'linux') throw Error('linux_required');
    const controller = new AbortController(), abort = () => controller.abort();
    process.on('SIGINT', abort); process.on('SIGTERM', abort);
    let report;
    try {
      console.error('[native-physical-preflight] Только чтение и offline plan; сеть и systemd не меняются');
      report = await collectNativePhysicalPreflight(options, { signal: controller.signal });
    } finally { process.off('SIGINT', abort); process.off('SIGTERM', abort); }
    console.log('=== CLEAN-VPN NATIVE PHYSICAL PREFLIGHT BEGIN ===');
    console.log(JSON.stringify(report, null, 2));
    console.log('=== CLEAN-VPN NATIVE PHYSICAL PREFLIGHT END ===');
    if (report.status !== 'ready-for-reviewed-trial-plan') process.exitCode = 1;
  }
} catch (error) {
  const safe = /^[a-z0-9_-]+$/.test(error?.message ?? '') ? error.message : 'invalid_arguments_or_inventory';
  console.error(`NATIVE_PHYSICAL_PREFLIGHT_FAILED: ${safe}; see --help. No settings changed.`);
  process.exitCode = 1;
}
