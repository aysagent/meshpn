#!/usr/bin/env node
/** Same-boot tunnel DNS recovery, network read-only unless --apply is explicit. */
import assert from 'node:assert/strict';
import { isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { openTunnelDnsJournal } from './lib/dns-tunnel-journal.mjs';

export function recoverTunnelDns(argv, open = openTunnelDnsJournal) {
  let directory, apply = false;
  const seen = new Set();
  for (const arg of argv) {
    const key = arg.split('=')[0]; assert.ok(!seen.has(key), `duplicate option: ${key}`); seen.add(key);
    if (arg === '--apply') apply = true;
    else if (arg.startsWith('--state-dir=')) {
      directory = arg.slice('--state-dir='.length);
      assert.ok(isAbsolute(directory) && resolve(directory) === directory, 'absolute normalized --state-dir required');
    } else throw Error(`unknown DNS recovery option: ${arg}`);
  }
  const journal = open(directory);
  try {
    assert.ok(journal.state, 'no tunnel DNS journal; no network changes made');
    return journal.restore({ apply });
  } finally { journal.release(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { console.log(JSON.stringify(recoverTunnelDns(process.argv.slice(2)), null, 2)); }
  catch (error) { console.error(`[clean-vpn DNS recovery] ${error.message}`); process.exitCode = 1; }
}
