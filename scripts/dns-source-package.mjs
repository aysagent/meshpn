#!/usr/bin/env node
/** Offline packaging only. Run without sudo; never invokes an installer. */
import { dirname, resolve, basename, join } from 'node:path';
import { realpath } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { packageDnsSource } from './lib/dns-source-package.mjs';

export function parseDnsSourcePackageArgs(args) {
  if (args.length === 1 && args[0] === '--help') return null;
  if (args.length !== 1 || !args[0].startsWith('--output=/')) throw new Error('DNS_PACKAGE_ARGUMENTS');
  const output = args[0].slice(9);
  if (output === '/' || resolve(output) !== output) throw new Error('DNS_PACKAGE_ARGUMENTS');
  return output;
}
async function main() {
  const output = parseDnsSourcePackageArgs(process.argv.slice(2));
  if (output === null) {
    console.log('Usage: node scripts/dns-source-package.mjs --output=/absolute/new-directory\nOffline JS/MJS snapshot and manifest. Run without sudo. Existing output is refused; parent must exist. No configuration, credentials, DNS queries, installation or service changes.');
    return;
  }
  const source = await realpath(dirname(dirname(fileURLToPath(import.meta.url))));
  const canonicalOutput = join(await realpath(dirname(output)), basename(output));
  console.log(JSON.stringify(await packageDnsSource({ source, output: canonicalOutput }), null, 2));
}
if (process.argv[1] === fileURLToPath(import.meta.url)) main().catch(() => {
  console.error('DNS_SOURCE_PACKAGE_REFUSED: output may contain an incomplete copy; it was not installed.'); process.exitCode = 1;
});
