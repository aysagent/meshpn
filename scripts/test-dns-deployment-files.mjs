import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, rm, writeFile, readFile, lstat, chmod, rename, symlink, unlink, link, readdir, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { runCommand } from './lib/transparent-acceptance.mjs';
import { compileDnsDeploymentFiles, dnsDeploymentFiles, readDnsDeploymentJournal, validateDnsDeploymentJournal } from './lib/dns-deployment-files.mjs';

const input = () => ({ adapter: { schema: 1, exitIp: '93.184.216.36', exitPort: 443, publicName: 'relay.example',
  listenPort: 1053, readyName: 'example.com', upstream: { schema: 1, transport: 'doh', hostname: 'resolver.example',
    port: 443, path: '/dns-query', bootstrap: { addresses: ['93.184.216.35'] }, trust: { mode: 'bundled' } },
  domainPolicy: { schema: 1, denySuffixes: ['internal'] } },
guard: { schema: 1, kind: 'clean-vpn-dns-boot-policy', enabled: true, firewallBackend: 'nf_tables',
  input: { schema: 1, client: 'vps2', id: 'a'.repeat(32) } } });

async function fixture(t) {
  const base = await realpath(await mkdtemp(join(tmpdir(), 'meshpn-deploy-files-'))); t.after(() => rm(base, { recursive: true, force: true }));
  const root = join(base, 'root'), directory = join(base, 'journal');
  for (const p of [root, directory, join(root, 'etc/systemd/system'), join(root, 'etc/clean-vpn/dns')]) await mkdir(p, { recursive: true, mode: 0o700 });
  let inactive = true;
  const files = compileDnsDeploymentFiles(input());
  const options = { root, directory, files, assertInactive: async () => inactive };
  return { root, directory, files, options, setActive: () => { inactive = false; },
    run: (operation, extra = {}) => dnsDeploymentFiles({ ...options, operation, ...extra }),
    target: (i = 0) => join(root, files[i].path) };
}
const absent = async (p) => assert.rejects(lstat(p), { code: 'ENOENT' });

test('file-only install and rollback preserve unrelated files, retain journal, do not enable units', async (t) => {
  const f = await fixture(t); const foreign = join(f.root, 'etc/keep'); await writeFile(foreign, 'baseline');
  const done = await f.run('install'); assert.equal(done.stage, 'installed'); assert.equal(done.activated, false);
  const record = await readDnsDeploymentJournal(f.directory); assert.equal(record.id, done.id);
  for (const [i, file] of f.files.entries()) {
    assert.equal(await readFile(f.target(i), 'utf8'), file.contents);
    const s = await lstat(f.target(i)); assert.equal(s.mode & 0o777, Number.parseInt(file.mode, 8)); assert.equal(s.nlink, 1);
    assert.ok(!file.path.includes('.wants/')); await absent(join(f.directory, `file-${i}`));
  }
  assert.deepEqual(await f.run('recover'), done); assert.deepEqual(await f.run('inspect'), done);
  assert.equal((await f.run('remove')).stage, 'removed');
  for (let i = 0; i < f.files.length; i++) await absent(f.target(i));
  assert.equal(await readFile(foreign, 'utf8'), 'baseline');
  assert.equal((await f.run('recover')).stage, 'removed'); assert.equal((await f.run('remove')).stage, 'removed');
  await assert.rejects(f.run('install'), /fresh deployment journal/);
});

test('same file transaction supports Radxa policy without changing dnsmasq or resolver', async (t) => {
  const f = await fixture(t), config = input();
  config.guard.input = { ...config.guard.input, client: 'radxa', usbInterface: 'usb0', usbAddress: '192.168.7.1' };
  const files = compileDnsDeploymentFiles(config);
  assert.deepEqual(files.map((x) => x.path), f.files.map((x) => x.path));
  await writeFile(join(f.root, 'etc/resolv.conf'), 'baseline'); await writeFile(join(f.root, 'etc/dnsmasq.conf'), 'no-resolv\n');
  assert.equal((await f.run('install', { files })).stage, 'installed');
  assert.deepEqual(JSON.parse(await readFile(f.target(4), 'utf8')), config.guard);
  assert.equal((await f.run('remove')).stage, 'removed');
  assert.equal(await readFile(join(f.root, 'etc/resolv.conf'), 'utf8'), 'baseline');
  assert.equal(await readFile(join(f.root, 'etc/dnsmasq.conf'), 'utf8'), 'no-resolv\n');
});

const cuts = ['prepared:renamed', 'prepared:dir-synced', ...Array.from({ length: 5 }, (_, i) => [`file-${i}:published`, `file-${i}:detached`]).flat(),
  'installed:renamed', 'installed:dir-synced'];
for (const point of cuts) test(`install interruption ${point}: exact recovery or explicit rollback`, async (t) => {
  for (const operation of ['recover', 'remove']) {
    const f = await fixture(t); let seen = false;
    await assert.rejects(f.run('install', { checkpoint: async (p) => { if (p === point) { seen = true; throw new Error('cut'); } } }), /cut/);
    assert.equal(seen, true); const r = await readDnsDeploymentJournal(f.directory);
    const result = await f.run(operation); assert.equal(result.id, r.id); assert.equal(result.stage, operation === 'recover' ? 'installed' : 'removed');
    for (const [i, file] of f.files.entries()) {
      if (operation === 'recover') { assert.equal(await readFile(f.target(i), 'utf8'), file.contents); assert.equal((await lstat(f.target(i))).nlink, 1); }
      else await absent(f.target(i));
    }
  }
});
for (const point of ['removing:renamed', ...Array.from({ length: 5 }, (_, i) => `file-${i}:removed`), 'removed:renamed']) {
  test(`removal interruption ${point}: recovery follows removal intent`, async (t) => {
    const f = await fixture(t); await f.run('install');
    await assert.rejects(f.run('remove', { checkpoint: async (p) => { if (p === point) throw new Error('cut'); } }), /cut/);
    assert.equal((await f.run('recover')).stage, 'removed');
    for (let i = 0; i < f.files.length; i++) await absent(f.target(i));
  });
}
test('pre-journal interruption never publishes or auto-adopts orphan staged files', async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.run('install', { checkpoint: async (p) => { if (p === 'prepared:file-synced') throw new Error('cut'); } }), /cut/);
  for (let i = 0; i < f.files.length; i++) await absent(f.target(i));
  await assert.rejects(f.run('recover'), { code: 'ENOENT' }); await assert.rejects(f.run('install'), /fresh deployment journal/);
});
test('foreign existing target, including byte-identical target, is never overwritten', async (t) => {
  const f = await fixture(t); await writeFile(f.target(4), f.files[4].contents);
  const before = await lstat(f.target(4)); await assert.rejects(f.run('install'), /target already exists/);
  assert.equal((await lstat(f.target(4))).ino, before.ino); assert.deepEqual(await readdir(f.directory), []);
});
for (const change of ['content', 'inode', 'mode', 'symlink', 'extra-hardlink', 'missing']) {
  test(`rollback preserves all files on ${change} conflict`, async (t) => {
    const f = await fixture(t); await f.run('install'); const journal = await readFile(join(f.directory, 'journal.json'));
    const path = f.target(4);
    if (change === 'content') await writeFile(path, 'foreign');
    if (change === 'inode') { await rename(path, `${path}.old`); await writeFile(path, f.files[4].contents, { mode: 0o600 }); }
    if (change === 'mode') await chmod(path, 0o644);
    if (change === 'symlink') { await rename(path, `${path}.old`); await symlink(`${path}.old`, path); }
    if (change === 'extra-hardlink') await link(path, `${path}.extra`);
    if (change === 'missing') await unlink(path);
    await assert.rejects(f.run('remove')); assert.deepEqual(await readFile(join(f.directory, 'journal.json')), journal);
    for (let i = 0; i < 4; i++) assert.equal(await readFile(f.target(i), 'utf8'), f.files[i].contents);
  });
}
test('mid-publication EEXIST refuses even an identical foreign inode', async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.run('install', { checkpoint: async (p) => {
    if (p === 'prepared:dir-synced') await writeFile(f.target(1), f.files[1].contents, { mode: 0o600 });
  } }), /foreign deployment inode/);
  for (const op of ['recover', 'remove']) await assert.rejects(f.run(op), /foreign deployment inode/);
  await absent(f.target(0)); // Whole-set check precedes the first publication.
});
test('active deployment or missing proof cannot install, inspect or remove', async (t) => {
  const f = await fixture(t); await assert.rejects(f.run('install', { assertInactive: undefined }), /proof required/);
  f.setActive(); await assert.rejects(f.run('install'), /proof required/); assert.deepEqual(await readdir(f.directory), []);
  const g = await fixture(t); await g.run('install'); g.setActive();
  for (const op of ['inspect', 'remove', 'recover']) await assert.rejects(g.run(op), /proof required/);
});
for (const change of ['parent-symlink', 'parent-writable', 'parent-replaced', 'journal-moved']) {
  test(`recovery rejects ${change}`, async (t) => {
    const f = await fixture(t); await f.run('install'); const p = join(f.root, 'etc/clean-vpn');
    if (change === 'parent-symlink') { await rename(p, `${p}.old`); await symlink(`${p}.old`, p); }
    if (change === 'parent-writable') await chmod(p, 0o777);
    if (change === 'parent-replaced') { await rename(p, `${p}.old`); await mkdir(p, { mode: 0o700 }); await rename(`${p}.old/dns`, `${p}/dns`); }
    if (change === 'journal-moved') {
      await rename(f.directory, `${f.directory}.old`); await mkdir(f.directory, { mode: 0o700 });
      await rename(`${f.directory}.old/journal.json`, `${f.directory}/journal.json`);
    }
    await assert.rejects(f.run('recover')); assert.equal(await readFile(f.target(0), 'utf8'), f.files[0].contents);
  });
}
test('manifest cannot add paths, traversal, modes, mismatched digests or executable payload files', async (t) => {
  for (const mutate of [(a) => a.push(a[0]), (a) => { a[0].path = '/etc/resolv.conf'; },
    (a) => { a[0].path = '/etc/systemd/system/../x'; }, (a) => { a[0].mode = '0777'; },
    (a) => { a[0].sha256 = '0'.repeat(64); }, (a) => { a[0].contents = ''; }]) {
    const f = await fixture(t); const files = structuredClone(f.files); mutate(files);
    await assert.rejects(f.run('install', { files })); assert.deepEqual(await readdir(f.directory), []);
  }
  const f = await fixture(t); await f.run('install'); const r = await readDnsDeploymentJournal(f.directory);
  for (const mutate of [(v) => { v.stage = 'active'; }, (v) => { v.extra = true; }, (v) => { v.files[0].path = '/etc/resolv.conf'; },
    (v) => { v.parents = []; }, (v) => { v.directoryIdentity = 'unknown'; }]) {
    const v = structuredClone(r); mutate(v); assert.throws(() => validateDnsDeploymentJournal(v));
  }
});

test('lost inactive proof prevents rollback setters and preserves removal intent', async (t) => {
  const f = await fixture(t); await f.run('install');
  await assert.rejects(f.run('remove', { checkpoint: async (p) => { if (p === 'removing:dir-synced') f.setActive(); } }), /proof required/);
  assert.equal((await readDnsDeploymentJournal(f.directory)).stage, 'removing');
  for (const [i, file] of f.files.entries()) assert.equal(await readFile(f.target(i), 'utf8'), file.contents);
});
test('corrupt journal cannot authorize rollback', async (t) => {
  const f = await fixture(t); await f.run('install'); await writeFile(join(f.directory, 'journal.json'), '{broken');
  await assert.rejects(f.run('remove'), SyntaxError);
  for (const [i, file] of f.files.entries()) assert.equal(await readFile(f.target(i), 'utf8'), file.contents);
});

for (const [operation, point, expected] of [
  ['install', 'prepared:dir-synced', 'installed'], ['install', 'file-0:published', 'installed'],
  ['install', 'file-2:detached', 'installed'], ['install', 'installed:dir-synced', 'installed'],
  ['remove', 'removing:dir-synced', 'removed'], ['remove', 'file-2:removed', 'removed'],
  ['remove', 'removed:dir-synced', 'removed'],
]) test(`actual SIGKILL under flock at ${point}`, async (t) => {
  const f = await fixture(t); if (operation === 'remove') await f.run('install');
  const lock = join(f.root, 'deployment.lock');
  const script = `
    import { dnsDeploymentFiles } from ${JSON.stringify(new URL('./lib/dns-deployment-files.mjs', import.meta.url).href)};
    import { ownsBootGuardLock } from ${JSON.stringify(new URL('./lib/dns-boot-guard.mjs', import.meta.url).href)};
    import { readdir, readFile } from 'node:fs/promises';
    const o = JSON.parse(process.argv[1]), point = process.argv[2];
    const infos = await Promise.all((await readdir('/proc/self/fdinfo')).map(n => readFile('/proc/self/fdinfo/' + n, 'utf8').catch(e => { if(e.code==='ENOENT') return ''; throw e; })));
    if (!infos.some(s => ownsBootGuardLock(s, process.pid))) throw new Error('lock missing');
    await dnsDeploymentFiles({ ...o, assertInactive: async () => true, checkpoint: async p => {
      if (p === point) { console.log('CUT_READY'); await new Promise(() => { setInterval(() => {}, 1000); }); }
    } });
    throw new Error('checkpoint not reached');`;
  const child = spawn('/usr/bin/flock', ['-n', '-E', '75', '-F', lock, process.execPath, '--input-type=module', '-e', script,
    JSON.stringify({ root: f.root, directory: f.directory, files: f.files, operation }), point], { stdio: ['ignore', 'pipe', 'pipe'] });
  const closed = once(child, 'close'); let output = '', errors = '', timer;
  try {
    await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error(`checkpoint timeout: ${errors}`)), 15000);
      child.on('error', reject); child.stderr.on('data', (s) => { errors += s; });
      child.stdout.on('data', (s) => { output += s; if (output.includes('CUT_READY\n')) resolve(); });
      child.once('close', () => reject(new Error(`early exit: ${errors}`)));
    });
    clearTimeout(timer);
    const conflict = await runCommand('/usr/bin/flock', ['-n', '-E', '75', '-F', lock, '/usr/bin/true']);
    assert.equal(conflict.code, 75); child.kill('SIGKILL');
    const [code, signal] = await closed; assert.equal(code, null); assert.equal(signal, 'SIGKILL');
  } finally { clearTimeout(timer); if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await closed; }
  const released = await runCommand('/usr/bin/flock', ['-n', '-E', '75', '-F', lock, '/usr/bin/true']); assert.equal(released.code, 0);
  assert.equal((await f.run('recover')).stage, expected);
  for (const [i, file] of f.files.entries()) {
    if (expected === 'installed') { assert.equal(await readFile(f.target(i), 'utf8'), file.contents); assert.equal((await lstat(f.target(i))).nlink, 1); }
    else await absent(f.target(i));
  }
});
