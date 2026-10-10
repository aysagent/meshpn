#!/usr/bin/env node
import { collectNativeSandboxPreflight, parseNativeSandboxPreflightArgs } from './lib/native-sandbox-preflight.mjs';

try {
  const options = parseNativeSandboxPreflightArgs(process.argv.slice(2));
  if (options.help) console.log('Usage: sudo node scripts/clean-vpn-native-sandbox-preflight.mjs --role=client|exit --name=SHORT --endpoint=IPv4 --port=1024..65535 --sandbox-cidr=IPv4/30\nRead-only eligibility inventory for an additive isolated network-namespace trial. No probes, namespace/veth/TUN/firewall/systemd writes, service changes or cleanup.');
  else {
    if (process.platform !== 'linux') throw Error('linux_required');
    const controller = new AbortController(), abort = () => controller.abort();
    process.on('SIGINT', abort); process.on('SIGTERM', abort);
    let report; try { report = await collectNativeSandboxPreflight(options, { signal: controller.signal }); }
    finally { process.off('SIGINT', abort); process.off('SIGTERM', abort); }
    console.log('=== CLEAN-VPN NATIVE SANDBOX PREFLIGHT BEGIN ===');
    console.log(JSON.stringify(report, null, 2));
    console.log('=== CLEAN-VPN NATIVE SANDBOX PREFLIGHT END ===');
    if (report.status !== 'ready-for-sandbox-design-review') process.exitCode = 1;
  }
} catch (error) {
  const safe = /^[a-z0-9 _-]+$/.test(error?.message ?? '') ? error.message.replaceAll(' ', '_') : 'invalid_arguments_or_inventory';
  console.error(`NATIVE_SANDBOX_PREFLIGHT_FAILED: ${safe}; see --help. No settings changed.`); process.exitCode = 1;
}
