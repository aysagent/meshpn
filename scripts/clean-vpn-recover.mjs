#!/usr/bin/env node
/** Explicit, same-boot recovery of --from-tun only. Default is a read-only network audit. */
import { pathToFileURL } from 'node:url';
import { openIngressJournal } from './lib/ingress-journal.mjs';
import { validateFromTun } from './lib/ingress-routing.mjs';

export function recoverIngress(argv) {
  const options = { name: null, directory: undefined, apply: false };
  const seen = new Set();
  for (const arg of argv) {
    const key = arg.split('=')[0];
    if (seen.has(key)) throw new Error(`duplicate option: ${key}`); seen.add(key);
    if (arg.startsWith('--from-tun=')) options.name = arg.slice('--from-tun='.length);
    else if (arg.startsWith('--state-dir=')) options.directory = arg.slice('--state-dir='.length);
    else if (arg === '--apply') options.apply = true;
    else throw new Error(`unknown recovery option: ${arg}`);
  }
  if (!options.name) throw new Error('Usage: node scripts/clean-vpn-recover.mjs --from-tun=wg0 [--state-dir=/absolute/path] [--apply]');
  validateFromTun({ fromTun: options.name, role: 'client' });
  const journal = openIngressJournal(options.directory);
  try { return journal.restore(options); } finally { journal.release(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { console.log(JSON.stringify(recoverIngress(process.argv.slice(2)), null, 2)); }
  catch (error) { console.error(`[clean-vpn recovery] ${error.message}`); process.exitCode = 1; }
}
