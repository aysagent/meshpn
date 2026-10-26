#!/usr/bin/env node
// Independent recovery for the explicitly labelled runtime LAB, not an
// application shutdown tool. Suitable for a transient unit's ExecStopPost.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export function cleanupLab(journal, invoke) {
  assert.equal(journal.schema, 1); assert.equal(journal.kind, 'native-runtime-lab-ownership');
  assert.match(journal.prefix, /^cvpnrt-[a-f0-9]{16}$/);
  const label = `org.meshpn.native-runtime-lab=${journal.prefix}`, removed = [];
  for (const type of ['container', 'volume', 'network']) {
    const list = type === 'container' ? ['ps', '-a'] : [type, 'ls'];
    const format = type === 'container' ? '{{.Names}}' : '{{.Name}}';
    const names = invoke([...list, '--filter', 'label=' + label, '--format', format]).trim().split('\n').filter(Boolean);
    assert.ok(names.length <= 32, 'unexpected_resource_count');
    for (const name of names) {
      assert.ok(name.startsWith(journal.prefix + '-') && /^[a-z0-9-]+$/.test(name), 'foreign_name_refused');
      const item = JSON.parse(invoke(type === 'container' ? ['inspect', name] : [type, 'inspect', name]))[0];
      assert.equal((type === 'container' ? item.Config.Labels : item.Labels)?.['org.meshpn.native-runtime-lab'], journal.prefix, 'foreign_label_refused');
      invoke(type === 'container' ? ['rm', '-f', name] : [type, 'rm', name]); removed.push({ type, name });
    }
  }
  return { status: 'cleaned', removed };
}
function main() {
  assert.equal(process.argv.length, 3, 'Usage: cleanup OWNERSHIP.json');
  const file = path.resolve(process.argv[2]);
  const s = fs.lstatSync(file); assert.ok(s.isFile() && s.uid === process.getuid() && !(s.mode & 0o077) && s.size < 16384, 'private_owned_journal_required');
  const j = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.ok(Array.isArray(j.cli) && j.cli.length > 0 && j.cli.length <= 8 && j.cli.every(v => typeof v === 'string' && v.length < 512));
  const invoke = args => execFileSync(j.cli[0], [...j.cli.slice(1), ...args], { encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024 });
  const result = cleanupLab(j, invoke);
  if (j.temp && fs.existsSync(j.temp)) {
    assert.equal(fs.realpathSync(path.dirname(j.temp)), fs.realpathSync(os.tmpdir()));
    assert.match(path.basename(j.temp), new RegExp('^' + j.prefix + '[A-Za-z0-9]{6}$'));
    const st = fs.lstatSync(j.temp); assert.ok(st.isDirectory() && st.uid === process.getuid() && !(st.mode & 0o077), 'foreign_temp_refused');
    fs.rmSync(j.temp, { recursive: true });
  }
  console.log(JSON.stringify(result));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
