#!/usr/bin/env node
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { openIpv6Runtime } from './lib/vpn-ipv6-runtime.mjs';

export function recoverIpv6(args, open = openIpv6Runtime) {
  assert.ok(args.length === 0 || args.length === 1 && args[0] === '--apply', 'only --apply is accepted');
  const runtime = open();
  try {
    if (!runtime.state) return { mode: 'no-journal', operations: 0 };
    runtime.audit();
    if (args.length) runtime.restore();
    return { mode: args.length ? 'restored' : 'dry-run', stage: runtime.state.stage,
      operations: runtime.state.count, tunnelRoute: runtime.state.dynamic };
  } finally { runtime.release(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { console.log(JSON.stringify(recoverIpv6(process.argv.slice(2)), null, 2)); }
  catch (error) { console.error(`[clean-vpn IPv6 recovery] ${error.message}`); process.exitCode = 1; }
}
