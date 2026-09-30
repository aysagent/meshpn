#!/usr/bin/env node
import assert from 'node:assert/strict';
import { updateHostService } from './lib/host-update.mjs';
try {
  assert.equal(process.getuid(), 0, 'root required');
  assert.equal(process.argv.length, 3, 'usage: node scripts/clean-vpn-update.mjs --release=/absolute/separate/release');
  assert.ok(process.argv[2].startsWith('--release='), 'only --release is accepted; service via SERVICE_NAME');
  console.log(JSON.stringify(updateHostService({ service: process.env.SERVICE_NAME || 'clean-vpn', release: process.argv[2].slice(10) }), null, 2));
} catch (error) {
  console.error(`[clean-vpn update] ${error.message}; no automatic restart/rollback; inspect installed wrapper and journals before starting`);
  process.exitCode = 1;
}
