#!/usr/bin/env node
import assert from 'node:assert/strict';
import { retireLegacyHost } from './lib/host-retire-legacy.mjs';
try {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--help') console.log('Usage: sudo node scripts/clean-vpn-retire-legacy.mjs [--apply]\nDefault: audit only. --apply backs up and removes ONLY four stopped legacy clean-vpn files, then daemon-reload. No network changes, stop/start, old-script execution or new installation. Partial failure requires backup review; never blindly retry/install.');
  else {
    assert.ok(args.length === 0 || args.length === 1 && args[0] === '--apply', 'only --apply accepted');
    assert.ok(process.platform === 'linux' && process.getuid() === 0, 'Linux root required');
    const report = retireLegacyHost({ apply: args.length === 1, onProgress: p => console.error(JSON.stringify(p)) });
    console.log(JSON.stringify(report, null, 2));
  }
} catch (e) { console.error(JSON.stringify(e.retirement ?? { status: 'refused', reason: e.message }, null, 2)); process.exitCode = 1; }
