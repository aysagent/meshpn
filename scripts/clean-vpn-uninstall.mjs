#!/usr/bin/env node
import assert from 'node:assert/strict';
import { uninstallHostService } from './lib/host-uninstall.mjs';
import { removeUsbGateway } from './lib/host-usb-gateway.mjs';

try {
  assert.equal(process.getuid(), 0, 'root required');
  assert.equal(process.argv.length, 2, 'no command-line options accepted; use SERVICE_NAME');
  const service = process.env.SERVICE_NAME || 'clean-vpn';
  console.log(JSON.stringify(uninstallHostService({ service,
    inspectExtras: () => { if (service === 'clean-vpn') removeUsbGateway(); },
    removeExtras: () => { if (service === 'clean-vpn') console.error(JSON.stringify(removeUsbGateway({ apply: true }))); },
  }), null, 2));
} catch (error) {
  console.error(`[clean-vpn uninstall] ${error.message}`);
  process.exitCode = 1;
}
