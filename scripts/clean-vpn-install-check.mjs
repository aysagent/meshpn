#!/usr/bin/env node
import assert from 'node:assert/strict';
import { assertFreshHostInstall } from './lib/host-install-check.mjs';
try {
  assert.equal(process.argv.length, 3, 'one service name required');
  assertFreshHostInstall({ service: process.argv[2] });
} catch (error) {
  console.error(`[clean-vpn-autostart] ${error.message}`);
  process.exitCode = 1;
}
