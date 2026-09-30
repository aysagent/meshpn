#!/usr/bin/env node
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { openHostRoutes } from './lib/vpn-host-routes.mjs';
export function recoverHost(args, open = openHostRoutes) {
  assert.ok(args.length === 0 || args.length === 1 && args[0] === '--apply', 'only --apply is accepted');
  const r = open();
  try {
    if (!r.state) return { mode: 'no-journal', operations: 0 };
    if (r.state.stage !== 'released') r.audit();
    if (args.length) r.restore();
    return { mode: args.length ? 'restored' : 'dry-run', stage: r.state.stage,
      routes: r.state.routes.length, rpFilterPending: r.state.rp !== null };
  } finally { r.release(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { console.log(JSON.stringify(recoverHost(process.argv.slice(2)), null, 2)); }
  catch (e) { console.error(`[clean-vpn host recovery] ${e.message}`); process.exitCode = 1; }
}
