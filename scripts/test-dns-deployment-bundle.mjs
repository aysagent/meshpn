import { deploymentHarness } from './fixtures/dns-deployment-harness.mjs';
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdir, chmod, writeFile, readFile, lstat, readdir, rename, symlink, link } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { runCommand } from './lib/transparent-acceptance.mjs';
import { inspectDnsInstalledBundle } from './lib/dns-installed-authority.mjs';
import { readDnsBundleJournal, validateDnsBundleJournal } from './lib/dns-deployment-bundle.mjs';

const hash = (v) => createHash('sha256').update(v).digest('hex');
const absent = (path) => assert.rejects(lstat(path), { code: 'ENOENT' });
const fixture = deploymentHarness;
test('bundle publication validates a private copy and inactive removal retains exact code', async (t) => {
  const f = await fixture(t), before = await inspectDnsInstalledBundle(f.source, process.getuid());
  const done = await f.ok('install'); assert.equal(done.stage, 'installed'); assert.equal(done.activated, false);
  const after = await inspectDnsInstalledBundle(f.target, process.getuid());
  assert.equal(after.sha256, before.sha256); assert.notEqual(after.rootIdentity, before.rootIdentity);
  assert.deepEqual(await f.ok('inspect'), done); assert.deepEqual(await f.ok('recover'), done);
  const removed = await f.ok('remove'); assert.equal(removed.stage, 'removed'); assert.equal(removed.codeRetained, true);
  await absent(f.target);
  assert.deepEqual(await inspectDnsInstalledBundle(join(f.directory, 'retired'), process.getuid()), after);
  assert.deepEqual(await f.ok('recover'), removed);
  assert.deepEqual(await inspectDnsInstalledBundle(f.source, process.getuid()), before);
  assert.notEqual((await f.run('install')).code, 0);
});
test('public bundle permissions do not depend on caller umask', async (t) => {
  const f = await fixture(t);
  // The child deliberately uses umask077 before staging.
  const r = await f.ok('install', ''); assert.equal(r.files, 4);
  const installed = await inspectDnsInstalledBundle(f.target, process.getuid());
  assert.equal(installed.sha256, f.options.expectedSha256);
});
for (const kind of ['directory', 'file', 'symlink']) test(`existing ${kind} at target is never adopted`, async (t) => {
  const f = await fixture(t);
  if (kind === 'directory') await mkdir(f.target);
  else if (kind === 'file') await writeFile(f.target, 'foreign');
  else await symlink(f.source, f.target);
  const before = await lstat(f.target);
  assert.notEqual((await f.run('install')).code, 0); assert.equal((await lstat(f.target)).ino, before.ino);
  assert.deepEqual(await readdir(f.directory), []);
});
for (const kind of ['digest', 'hardlink', 'mode', 'unlisted', 'missing-entry']) test(`unapproved source ${kind} cannot stage`, async (t) => {
  const f = await fixture(t), path = join(f.source, 'scripts/dns-client.mjs');
  if (kind === 'digest') await writeFile(path, 'changed');
  if (kind === 'hardlink') await link(path, join(f.base, 'other-link'));
  if (kind === 'mode') await chmod(path, 0o666);
  if (kind === 'unlisted') await writeFile(join(f.source, 'extra'), 'unexpected');
  if (kind === 'missing-entry') {
    const m = JSON.parse(await readFile(join(f.source, 'bundle.json'), 'utf8')); delete m.files['scripts/dns-boot-guard.mjs'];
    await writeFile(join(f.source, 'bundle.json'), JSON.stringify(m));
  }
  assert.notEqual((await f.run('install')).code, 0); assert.deepEqual(await readdir(f.directory), []); await absent(f.target);
});
test('an incorrect approval digest and an inactive-proof failure leave no staging', async (t) => {
  const f = await fixture(t);
  for (const extra of [{ expectedSha256: '0'.repeat(64) }, { inactive: false }]) {
    assert.notEqual((await f.run('install', '', extra)).code, 0); assert.deepEqual(await readdir(f.directory), []);
  }
});
test('same-device different-mount staging is refused before any writes', async (t) => {
  const f = await fixture(t), r = await f.run('install', '', { crossMount: true });
  assert.notEqual(r.code, 0); assert.match(r.stderr, /cross-mount bundle publication unsupported/);
  assert.deepEqual(await readdir(f.directory), []); await absent(f.target);
});
test('publication requires an actual inherited exclusive flock', async (t) => {
  const f = await fixture(t), r = await f.run('install', '', { withoutLock: true });
  assert.notEqual(r.code, 0); assert.deepEqual(await readdir(f.directory), []); await absent(f.target);
});
test('source drift during staging cannot become a journal or published bundle', async (t) => {
  const f = await fixture(t), r = await f.run('install',
    `if(point==='bundle:staged') await writeFile(options.source+'/scripts/dns-client.mjs','changed');`);
  assert.notEqual(r.code, 0); await absent(f.target); await absent(join(f.directory, 'journal.json'));
  await inspectDnsInstalledBundle(join(f.directory, 'bundle'), process.getuid());
});
test('unrecorded staging after a pre-journal failure is retained for review', async (t) => {
  const f = await fixture(t); assert.notEqual((await f.run('install', `if(point==='bundle:staged') throw new Error('CUT');`)).code, 0);
  await absent(f.target); await absent(join(f.directory, 'journal.json'));
  await inspectDnsInstalledBundle(join(f.directory, 'bundle'), process.getuid());
  assert.notEqual((await f.run('recover')).code, 0); assert.notEqual((await f.run('install')).code, 0);
});
test('a foreign directory appearing immediately before move is not overwritten or nested into', async (t) => {
  const f = await fixture(t);
  const result = await f.run('install', `if(point==='bundle:before-move') await mkdir(options.root+'/opt/clean-vpn');`);
  assert.notEqual(result.code, 0); assert.deepEqual(await readdir(f.target), []);
  await inspectDnsInstalledBundle(join(f.directory, 'bundle'), process.getuid());
  assert.notEqual((await f.run('recover')).code, 0);
});
for (const kind of ['content', 'inode', 'mode', 'extra', 'parent', 'active']) test(`installed drift ${kind} prevents quarantine`, async (t) => {
  const f = await fixture(t); await f.ok('install'); const path = join(f.target, 'scripts/dns-client.mjs');
  if (kind === 'content') await writeFile(path, 'foreign');
  if (kind === 'inode') { const bytes = await readFile(path); await rename(path, join(f.base, 'saved')); await writeFile(path, bytes); }
  if (kind === 'mode') await chmod(path, 0o600);
  if (kind === 'extra') await writeFile(join(f.target, 'foreign'), 'operator');
  if (kind === 'parent') { await rename(join(f.root, 'opt'), join(f.root, 'old-opt')); await mkdir(join(f.root, 'opt')); }
  assert.notEqual((await f.run('remove', '', kind === 'active' ? { inactive: false } : {})).code, 0);
  await absent(join(f.directory, 'retired')); assert.equal((await readDnsBundleJournal(f.directory)).stage, 'installed');
});
test('a prepared bundle may be rolled back without publication', async (t) => {
  const f = await fixture(t);
  assert.notEqual((await f.run('install', `if(point==='prepared:dir-synced') throw new Error('CUT');`)).code, 0);
  await absent(f.target); assert.equal((await f.ok('remove')).stage, 'removed'); await absent(f.target);
});
for (const point of ['bundle:staged', 'bundle:before-move']) test(`loss of inactivity at ${point} still prevents visible code publication`, async (t) => {
  const f = await fixture(t);
  assert.notEqual((await f.run('install', `if(point===${JSON.stringify(point)}) options.inactive=false;`)).code, 0);
  await absent(f.target); await lstat(join(f.directory, 'bundle'));
});
test('journal rejects unknown fields, arbitrary paths, stages, and missing service entrypoints', async (t) => {
  const f = await fixture(t); await f.ok('install'); const journal = await readDnsBundleJournal(f.directory);
  for (const mutate of [(v) => { v.target = '/etc'; }, (v) => { v.stage = 'active'; },
    (v) => { v.bundle.files['scripts/../bad.mjs'] = '1:2:3:4'; },
    (v) => { delete v.bundle.files['scripts/dns-exit-adapter.mjs']; }]) {
    const copy = structuredClone(journal); mutate(copy); assert.throws(() => validateDnsBundleJournal(copy));
  }
});
for (const [operation, point, expected] of [
  ['install', 'prepared:dir-synced', 'installed'], ['install', 'bundle:published', 'installed'],
  ['install', 'installed:dir-synced', 'installed'], ['remove', 'removing:dir-synced', 'removed'],
  ['remove', 'bundle:retired', 'removed'], ['remove', 'removed:dir-synced', 'removed'],
]) test(`actual bundle SIGKILL at ${point} resumes only the recorded direction`, async (t) => {
  const f = await fixture(t); if (operation === 'remove') await f.ok('install');
  const child = spawn('/usr/bin/unshare', f.args(operation,
    `if(point===${JSON.stringify(point)}) {console.log('CUT_READY'); await new Promise(()=>setInterval(()=>{},1000));}`), { stdio: ['ignore', 'pipe', 'pipe'] });
  const closed = once(child, 'close'); let output = '', errors = '', timer;
  try {
    await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error(`checkpoint timeout: ${errors}`)), 15000);
      child.on('error', reject); child.stderr.on('data', (s) => { errors += s; });
      child.stdout.on('data', (s) => { output += s; if (output.includes('CUT_READY\n')) resolve(); });
      child.once('close', () => reject(new Error(`early exit: ${errors}`)));
    });
    clearTimeout(timer); assert.equal((await runCommand('/usr/bin/flock', ['-n', '-E', '75', f.lock, '/usr/bin/true'])).code, 75);
    child.kill('SIGKILL'); assert.deepEqual(await closed, [null, 'SIGKILL']);
  } finally { clearTimeout(timer); if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await closed; }
  assert.equal((await f.ok('recover')).stage, expected);
  if (expected === 'removed') await absent(f.target); else await inspectDnsInstalledBundle(f.target, process.getuid());
});
