#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { upgradeUsbDnsGuard } from './lib/host-usb-dns-upgrade.mjs';
try {
  const args = process.argv.slice(2);
  assert.ok(args.length === 0 || (args.length === 1 && args[0] === '--apply'), 'use [--apply]');
  assert.equal(process.getuid(), 0, 'root required');
  assert.equal(process.env.SERVICE_NAME || 'clean-vpn', 'clean-vpn');
  assert.equal(fs.readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
  assert.equal(fs.readlinkSync('/proc/self/ns/net'), fs.readlinkSync('/proc/1/ns/net'));
  console.log(JSON.stringify(upgradeUsbDnsGuard({ apply: args.includes('--apply') }), null, 2));
} catch (error) {
  console.error(JSON.stringify({ status: 'refused-or-incomplete', error: error.message,
    note: 'No guard/networkd/USB restart or automatic rollback. VPN/SNAT may remain stopped; keep USB rescue. Review partial upgrade.' }));
  process.exitCode = 1;
}
