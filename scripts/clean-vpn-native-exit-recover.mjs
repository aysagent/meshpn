#!/usr/bin/env node
/** Same-boot exact recovery for the transient native exit network. */
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { openNativeExitTrialNetwork } from './lib/native-exit-trial-network.mjs';

export function recoverNativeExit(args, open = openNativeExitTrialNetwork) {
  assert.ok(args.length === 0 || args.length === 1 && args[0] === '--apply', 'only --apply is accepted');
  const owner = open();
  try {
    if (!owner.state) { owner.assertAvailable(); return { mode: 'no-journal', stage: 'absent', operations: 0 }; }
    if (owner.state.stage === 'released') { owner.assertAvailable(); return { mode: args.length ? 'already-released' : 'dry-run', stage: 'released', operations: 0 }; }
    return owner.restore({ apply: args.length === 1 });
  } finally { owner.release(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { console.log(JSON.stringify(recoverNativeExit(process.argv.slice(2)), null, 2)); }
  catch (error) { console.error(`[clean-vpn native exit recovery] ${error.message}`); process.exitCode = 1; }
}
