#!/usr/bin/env node
import assert from 'node:assert/strict';
import { uninstallHostService } from './lib/host-uninstall.mjs';

try {
  assert.equal(process.getuid(), 0, 'root required');
  assert.equal(process.argv.length, 2, 'no command-line options accepted; use SERVICE_NAME');
  console.log(JSON.stringify(uninstallHostService({ service: process.env.SERVICE_NAME || 'clean-vpn' }), null, 2));
} catch (error) {
  console.error(`[clean-vpn uninstall] ${error.message}`);
  process.exitCode = 1;
}
