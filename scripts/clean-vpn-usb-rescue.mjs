#!/usr/bin/env node
import { installUsbRescue } from './lib/host-usb-rescue.mjs';
try {
  const args = process.argv.slice(2);
  if (args.length > 1 || args.some(a => !['--apply', '--help'].includes(a))) throw Error('Usage: sudo node scripts/clean-vpn-usb-rescue.mjs [--apply]');
  if (args.includes('--help')) console.log('Radxa USB rescue: plan by default; --apply adds USB-only SSH 192.168.7.1:2222 with existing authentication. No gadget/SSH/VPN/networkd restart, firewall changes or reboot. Partial installation is retained on failure; do not retry blindly.');
  else installUsbRescue({ apply: args.includes('--apply') });
} catch (e) { console.error(`[usb-rescue] ${e.message}`); process.exitCode = 1; }
