#!/usr/bin/env node
// Allowlisted context only; never sends private files or unrelated work to a builder.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
assert.equal(process.argv.length, 3, 'Usage: node scripts/clean-vpn-native-runtime-context.mjs NEW_DIRECTORY');
const output = path.resolve(process.argv[2]); assert.equal(fs.existsSync(output), false, 'new_context_required');
const files = ['scripts/clean-vpn-native-runtime.mjs', 'scripts/clean-vpn-native-runtime-health.mjs',
  'scripts/lib/native-runtime-plan.mjs', 'scripts/lib/native-relay-health.mjs', 'scripts/lib/native-transparent-network.mjs', 'scripts/containers/native-runtime-entrypoint.sh',
  'scripts/containers/clean-vpn-native-runtime.Containerfile', 'fixtures/native-tls-profiles/cold-h2.json'];
for (const dir of ['native/clean_vpn', 'native/boring_tls', 'native/boring_tls/patches']) {
  for (const f of fs.readdirSync(path.join(root, dir))) if (f === 'CMakeLists.txt' || /\.(cc|c|h|hpp|patch)$/.test(f)) files.push(`${dir}/${f}`);
}
const hashes = {};
for (const file of files.sort()) {
  const source = path.join(root, file); assert.ok(fs.lstatSync(source).isFile(), 'regular_source_required');
  const data = fs.readFileSync(source); hashes[file] = createHash('sha256').update(data).digest('hex');
  const dest = path.join(output, file); fs.mkdirSync(path.dirname(dest), { recursive: true }); fs.writeFileSync(dest, data);
}
fs.mkdirSync(path.join(output, 'artifacts'));
fs.writeFileSync(path.join(output, 'provenance.json'), JSON.stringify({ schema: 1, kind: 'native-runtime-sources',
  revision: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(),
  note: 'File hashes describe the actual worktree, including uncommitted changes. Base digest and binary hash are separate build evidence.', files: hashes }, null, 2) + '\n');
console.log(output);
