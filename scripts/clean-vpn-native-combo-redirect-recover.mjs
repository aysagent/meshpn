#!/usr/bin/env node
/** Exact same-boot recovery for the direct-trial HTTPS redirect overlay. */
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { openNativeComboRedirectJournal } from './lib/native-combo-redirect-journal.mjs';

export function recoverNativeComboRedirect(args, open = openNativeComboRedirectJournal) {
  assert.ok(args.length === 0 || args.length === 1 && args[0] === '--apply', 'only --apply is accepted');
  const journal = open();
  try {
    if (!journal.state) {
      journal.assertAvailable();
      return { mode: 'no-journal', stage: 'absent', operations: 0 };
    }
    if (journal.state.stage === 'released') {
      journal.assertAvailable();
      return { mode: args.length ? 'already-released' : 'dry-run', stage: 'released', operations: 0 };
    }
    return journal.restore({ apply: args.length === 1 });
  } finally { journal.release(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { console.log(JSON.stringify(recoverNativeComboRedirect(process.argv.slice(2)), null, 2)); }
  catch (error) { console.error(`[clean-vpn combo redirect recovery] ${error.message}`); process.exitCode = 1; }
}
