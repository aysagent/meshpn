import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, rm, writeFile, readFile, lstat, chmod, rename, symlink, unlink, link, readdir, realpath } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { runCommand } from './lib/transparent-acceptance.mjs';
import { compileDnsDeploymentFiles, compileDnsClientDeploymentFiles, dnsDeploymentFiles, readDnsDeploymentJournal, validateDnsDeploymentJournal } from './lib/dns-deployment-files.mjs';
import { DNS_NETWORKD_POLICY, DNS_NETWORKD_CONTENTS, dnsNetworkdPolicyArtifact, assertDnsNetworkdUnmanaged } from './lib/dns-networkd-policy.mjs';
import { compileDnsControllerServicePlan } from './lib/dns-controller-service-plan.mjs';
import { createHash } from 'node:crypto';

const input = () => ({ adapter: { schema: 1, exitIp: '93.184.216.36', exitPort: 443, publicName: 'relay.example',
  listenPort: 1053, readyName: 'example.com', upstream: { schema: 1, transport: 'doh', hostname: 'resolver.example',
    port: 443, path: '/dns-query', bootstrap: { addresses: ['93.184.216.35'] }, trust: { mode: 'bundled' } },
  domainPolicy: { schema: 1, denySuffixes: ['internal'] } },
guard: { schema: 1, kind: 'clean-vpn-dns-boot-policy', enabled: true, firewallBackend: 'nf_tables',
  input: { schema: 1, client: 'vps2', id: 'a'.repeat(32) } } });

const clientInput = () => ({ ...input(), config: { schema: 1, kind: 'clean-vpn-dns-client', client: 'vps2',
  uplink: 'eth0', networkFile: { path: '/run/systemd/network/10-netplan-eth0.network', sha256: 'c'.repeat(64) },
  adapterPort: 1053, readyName: 'example.com', domainPolicy: { schema: 1, denySuffixes: ['internal'] } },
  bundle: JSON.stringify({ schema: 1, kind: 'clean-vpn-dns-code-bundle', files: {
    'scripts/dns-client.mjs': 'd'.repeat(64), 'scripts/lib/dns-installed-authority.mjs': 'e'.repeat(64) } }),
  secret: Buffer.from(Array.from({ length: 32 }, (_, i) => i * 8)) });
async function fixture(t, controller = false, client = false) {
  const base = await realpath(await mkdtemp(join(tmpdir(), 'meshpn-deploy-files-'))); t.after(() => rm(base, { recursive: true, force: true }));
  const root = join(base, 'root'), directory = join(base, 'journal');
  for (const p of [root, directory, join(root, 'etc/systemd/system'), join(root, 'etc/systemd/network'), join(root, 'etc/clean-vpn/dns')]) await mkdir(p, { recursive: true, mode: 0o700 });
  let inactive = true;
  const files = client ? compileDnsClientDeploymentFiles(clientInput()) : compileDnsDeploymentFiles({ ...input(), controller });
  for (const file of files) await mkdir(dirname(join(root, file.path)), { recursive: true, mode: 0o700 });
  const options = { root, directory, files, assertInactive: async () => inactive };
  return { root, directory, files, options, setActive: () => { inactive = false; },
    run: (operation, extra = {}) => dnsDeploymentFiles({ ...options, operation, ...extra }),
    target: (i = 0) => join(root, files[i].path) };
}
const absent = async (p) => assert.rejects(lstat(p), { code: 'ENOENT' });

test('fixed dependency detach refuses legacy sets without altering installed files', async (t) => {
  for (const controller of [false, true]) {
    const f = await fixture(t, controller); await f.run('install');
    await assert.rejects(f.run('detach'));
    assert.equal((await readDnsDeploymentJournal(f.directory)).stage, 'installed');
    for (const [i, file] of f.files.entries()) assert.deepEqual(await readFile(f.target(i)), Buffer.from(file.contents));
  }
});
test('dependency detach stops on loss of OS proof before deleting another file', async (t) => {
  const f = await fixture(t, true, true); await f.run('install');
  await assert.rejects(f.run('detach', { checkpoint: async (point) => {
    if (point === 'file-12:removed') f.setActive();
  } }), /inactive deployment proof/);
  await absent(f.target(12));
  for (let i = 0; i < 12; i++) await lstat(f.target(i));
  await assert.rejects(f.run('recover'), /inactive deployment proof/);
  assert.equal((await readDnsDeploymentJournal(f.directory)).stage, 'detaching');
});

test('private client set binds exact config/bundle/guard and preserves the binary PSK', async (t) => {
  const input = clientInput(), compiled = compileDnsClientDeploymentFiles(input);
  input.secret.fill(0); assert.notDeepEqual(compiled[10].contents, input.secret);
  const f = await fixture(t, true, true); assert.equal(f.files.length, 13);
  const permit = JSON.parse(f.files[12].contents);
  assert.equal(permit.configSha256, createHash('sha256').update(f.files[11].contents).digest('hex'));
  assert.equal(permit.bundleSha256, createHash('sha256').update(clientInput().bundle).digest('hex'));
  assert.equal(permit.guardId, clientInput().guard.input.id);
  await f.run('install');
  assert.deepEqual(await readFile(f.target(10)), clientInput().secret);
  for (const i of [10, 11, 12]) assert.equal((await lstat(f.target(i))).mode & 0o7777, 0o600);
  const journal = await readDnsDeploymentJournal(f.directory);
  assert.equal(journal.files.length, 13); assert.ok(Buffer.byteLength(JSON.stringify(journal)) <= 8192);
  for (const file of journal.files) assert.equal(Object.hasOwn(file, 'contents'), false);
  assert.equal((await f.run('recover')).files, 13); await f.run('remove');
  for (let i = 0; i < 13; i++) await absent(f.target(i));
});
test('client opt-in is last to publish, first to revoke on inactive rollback', async (t) => {
  const f = await fixture(t, true, true), published = [], removed = [];
  await f.run('install', { checkpoint: async (name) => {
    if (!name.endsWith(':published')) return;
    published.push(name);
    if (name !== 'file-12:published') await absent(f.target(12));
    else for (let i = 0; i < 12; i++) assert.equal((await lstat(f.target(i))).nlink, 1);
  } });
  await f.run('remove', { checkpoint: async (name) => {
    if (!name.endsWith(':removed')) return;
    removed.push(name); await absent(f.target(12));
  } });
  assert.deepEqual(published, Array.from({ length: 13 }, (_, i) => `file-${i}:published`));
  assert.deepEqual(removed, Array.from({ length: 13 }, (_, i) => `file-${12 - i}:removed`));
});
test('private client set refuses mismatched inputs and invalid keys without serializing the key', () => {
  for (const mutate of [(v) => { v.config.adapterPort++; }, (v) => { v.config.readyName = 'different.example'; },
    (v) => { v.config.domainPolicy.denySuffixes = ['elsewhere']; }, (v) => { v.secret = Buffer.alloc(31); },
    (v) => { v.secret = 'f'.repeat(32); }, (v) => { v.bundle = '{}'; },
    (v) => { v.config.client = 'radxa'; }, (v) => { v.guard.input.client = 'radxa'; }]) {
    const v = clientInput(); mutate(v); assert.throws(() => compileDnsClientDeploymentFiles(v));
  }
});
test('private set revalidates raw files: incomplete/reordered sets and altered opt-in cannot stage', async (t) => {
  for (const mutate of [(v) => v.splice(12, 1), (v) => v.splice(6, 4), (v) => v.reverse(),
    (v) => { const p = JSON.parse(v[12].contents); p.guardId = '0'.repeat(32); v[12].contents = JSON.stringify(p); },
    (v) => { const p = JSON.parse(v[12].contents); p.configSha256 = '0'.repeat(64); v[12].contents = JSON.stringify(p); },
    (v) => { v[0].contents += 'ExecStart=/bin/false\n'; },
    (v) => { const c = JSON.parse(v[2].contents); c.denySuffixes = []; v[2].contents = JSON.stringify(c); }]) {
    const f = await fixture(t, true, true);
    const files = f.files.map((v) => ({ ...v })); mutate(files);
    for (const file of files) file.sha256 = createHash('sha256').update(file.contents).digest('hex');
    await assert.rejects(f.run('install', { files })); assert.deepEqual(await readdir(f.directory), []);
  }
});
test('an existing PSK is never adopted even when its bytes match', async (t) => {
  const f = await fixture(t, true, true); await writeFile(f.target(10), clientInput().secret, { mode: 0o600 });
  const before = await lstat(f.target(10)); await assert.rejects(f.run('install'), /already exists/);
  assert.equal((await lstat(f.target(10))).ino, before.ino); assert.deepEqual(await readdir(f.directory), []);
  await absent(f.target(12));
});
test('private input buffers are copied before publication checkpoints', async (t) => {
  const f = await fixture(t, true, true);
  await f.run('install', { checkpoint: async (name) => { if (name === 'prepared:dir-synced') f.files[10].contents.fill(0); } });
  assert.deepEqual(await readFile(f.target(10)), clientInput().secret);
});
test('older controller journal never adds credentials or client opt-in on recovery', async (t) => {
  const f = await fixture(t, true); await f.run('install');
  assert.equal((await f.run('recover', { files: compileDnsClientDeploymentFiles(clientInput()) })).files, 10);
  for (const file of compileDnsClientDeploymentFiles(clientInput()).slice(10)) await absent(join(f.root, file.path));
});

test('opt-in full VPS2 file set journals and removes all controller units/drop-ins without activation', async (t) => {
  const f = await fixture(t, true); assert.equal(f.files.length, 10);
  assert.deepEqual(f.files.slice(6), compileDnsControllerServicePlan({ schema: 1, client: 'vps2', firewallBackend: 'nf_tables' }).files);
  assert.equal((await f.run('install')).files, 10);
  assert.equal((await f.run('recover')).activated, false);
  const record = await readDnsDeploymentJournal(f.directory); assert.equal(record.files.length, 10);
  assert.ok(Buffer.byteLength(JSON.stringify(record)) <= 8192);
  for (const [i, file] of f.files.entries()) assert.equal(await readFile(f.target(i), 'utf8'), file.contents);
  await f.run('remove'); for (let i = 0; i < f.files.length; i++) await absent(f.target(i));
});
test('old six-file journals recover without implicitly adding controller units', async (t) => {
  const f = await fixture(t); await f.run('install');
  assert.equal((await f.run('recover', { files: compileDnsDeploymentFiles({ ...input(), controller: true }) })).files, 6);
  for (const file of compileDnsControllerServicePlan({ schema: 1, client: 'vps2', firewallBackend: 'nf_tables' }).files)
    await absent(join(f.root, file.path));
});
test('controller group refuses partial sets, missing exclusion, rewritten units and mixed backends before staging', async (t) => {
  const legacy = compileDnsControllerServicePlan({ schema: 1, client: 'vps2', firewallBackend: 'legacy' }).files;
  for (const mutate of [(v) => v.splice(8, 1), (v) => v.splice(5, 1),
    (v) => { v[6] = legacy[0]; }, (v) => { v.splice(6, 4, ...legacy); }, (v) => {
      v[9].contents = '[Unit]\nAfter=network-online.target\n';
      v[9].sha256 = createHash('sha256').update(v[9].contents).digest('hex');
    }]) {
    const f = await fixture(t, true), files = structuredClone(f.files); mutate(files);
    await assert.rejects(f.run('install', { files })); assert.deepEqual(await readdir(f.directory), []);
  }
  const bad = input(); bad.guard.input = { ...bad.guard.input, client: 'radxa', usbInterface: 'usb0', usbAddress: '192.168.7.1' };
  assert.throws(() => compileDnsDeploymentFiles({ ...bad, controller: true }));
  assert.throws(() => compileDnsDeploymentFiles({ ...input(), controller: 'yes' }));
});
test('foreign manager drop-in edit prevents removal of the entire installed file set', async (t) => {
  const f = await fixture(t, true); await f.run('install');
  await writeFile(f.target(8), '[Unit]\nDescription=operator change\n');
  await assert.rejects(f.run('remove'));
  for (const [i, file] of f.files.entries()) assert.equal(await readFile(f.target(i), 'utf8'), i === 8 ? '[Unit]\nDescription=operator change\n' : file.contents);
});

test('networkd exclusion is a fixed artifact for exactly eight hexadecimal name characters', () => {
  const f = dnsNetworkdPolicyArtifact(); assert.equal(f.path, DNS_NETWORKD_POLICY); assert.equal(f.mode, '0644');
  assert.equal(f.contents, DNS_NETWORKD_CONTENTS);
  assert.equal(f.contents.split('\n').filter((v) => v.startsWith('Name=')).join(''), `Name=cvdns${'[0-9a-f]'.repeat(8)}`);
  assert.match(f.contents, /\[Link\]\nUnmanaged=yes\n$/); assert.doesNotMatch(f.contents, /DNS=|DHCP=|Address=|eth0|wg0/);
  assert.equal(assertDnsNetworkdUnmanaged({ name: 'cvdns0123abcd', ifindex: 3, state: 'ADMIN_STATE=unmanaged\n' }), true);
  for (const state of ['', 'ADMIN_STATE=configured\n', 'ADMIN_STATE=unmanaged\nADMIN_STATE=configured\n', 'x'.repeat(65537)])
    assert.throws(() => assertDnsNetworkdUnmanaged({ name: 'cvdns0123abcd', ifindex: 3, state }));
  for (const name of ['eth0', 'cvdns', 'cvdns1234567', 'cvdns123456789', 'cvdnsABCDEF12', 'cvdns1234567z'])
    assert.throws(() => assertDnsNetworkdUnmanaged({ name, ifindex: 3, state: 'ADMIN_STATE=unmanaged\n' }));
  for (const ifindex of [1, 0, '3', 2147483648]) assert.throws(() => assertDnsNetworkdUnmanaged({ name: 'cvdns0123abcd', ifindex, state: 'ADMIN_STATE=unmanaged\n' }));
});
test('legacy five-file VPS2 journal can recover/remove but is not silently upgraded', async (t) => {
  const f = await fixture(t), files = f.files.filter((v) => v.path !== DNS_NETWORKD_POLICY);
  await f.run('install', { files }); assert.equal((await f.run('recover')).files, 5);
  await absent(join(f.root, DNS_NETWORKD_POLICY)); await f.run('remove');
});
test('networkd policy refuses foreign contents even with a matching digest', async (t) => {
  const f = await fixture(t), files = structuredClone(f.files);
  const policy = files.find((v) => v.path === DNS_NETWORKD_POLICY);
  policy.contents = '[Match]\nName=*\n[Link]\nUnmanaged=yes\n';
  const { createHash } = await import('node:crypto'); policy.sha256 = createHash('sha256').update(policy.contents).digest('hex');
  await assert.rejects(f.run('install', { files })); assert.deepEqual(await readdir(f.directory), []);
});
test('existing networkd exclusion is never adopted and drift prevents whole-set removal', async (t) => {
  const f = await fixture(t), path = join(f.root, DNS_NETWORKD_POLICY);
  await writeFile(path, DNS_NETWORKD_CONTENTS); const before = await lstat(path);
  await assert.rejects(f.run('install'), /already exists/); assert.equal((await lstat(path)).ino, before.ino);
  assert.deepEqual(await readdir(f.directory), []);
  await unlink(path); await f.run('install'); await writeFile(path, 'foreign policy');
  await assert.rejects(f.run('remove')); assert.equal(await readFile(f.target(), 'utf8'), f.files[0].contents);
});
test('same-device bind mount is rejected before staging or publishing artifacts', async (t) => {
  const f = await fixture(t), target = join(f.root, 'etc/systemd/network');
  const script = `
    import assert from 'node:assert/strict';
    import { readlink, readdir, lstat } from 'node:fs/promises';
    import { execFileSync } from 'node:child_process';
    import { dnsDeploymentFiles } from ${JSON.stringify(new URL('./lib/dns-deployment-files.mjs', import.meta.url).href)};
    const options = JSON.parse(process.argv[1]), target = process.argv[2], parentNamespace = process.argv[3];
    assert.notEqual(await readlink('/proc/self/ns/mnt'), parentNamespace);
    const before = await lstat(target);
    execFileSync('/usr/bin/mount', ['--bind', target, target]);
    assert.equal((await lstat(target)).dev, before.dev);
    await assert.rejects(dnsDeploymentFiles({ ...options, operation: 'install', assertInactive: async () => true }), /cross-mount/);
    assert.deepEqual(await readdir(options.directory), []);
    for (const f of options.files) await assert.rejects(lstat(options.root + f.path), { code: 'ENOENT' });
    console.log('CROSS_MOUNT_REFUSED');`;
  const { readlink } = await import('node:fs/promises');
  const r = await runCommand('/usr/bin/unshare', ['--user', '--map-root-user', '--mount', '--propagation', 'private', '--fork',
    process.execPath, '--input-type=module', '-e', script, JSON.stringify({ root: f.root, directory: f.directory, files: f.files }),
    target, await readlink('/proc/self/ns/mnt')]);
  assert.equal(r.code, 0, r.stderr); assert.equal(r.reason, null); assert.equal(r.stdout.trim(), 'CROSS_MOUNT_REFUSED');
  assert.deepEqual(await readdir(f.directory), []);
});

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
  assert.deepEqual(files.map((x) => x.path), f.files.filter((x) => x.path !== DNS_NETWORKD_POLICY).map((x) => x.path));
  assert.equal(files.length, 5); assert.equal(f.files.length, 6);
  await writeFile(join(f.root, 'etc/resolv.conf'), 'baseline'); await writeFile(join(f.root, 'etc/dnsmasq.conf'), 'no-resolv\n');
  assert.equal((await f.run('install', { files })).stage, 'installed');
  assert.deepEqual(JSON.parse(await readFile(f.target(4), 'utf8')), config.guard);
  assert.equal((await f.run('remove')).stage, 'removed');
  assert.equal(await readFile(join(f.root, 'etc/resolv.conf'), 'utf8'), 'baseline');
  assert.equal(await readFile(join(f.root, 'etc/dnsmasq.conf'), 'utf8'), 'no-resolv\n');
});

const cuts = ['prepared:renamed', 'prepared:dir-synced', ...Array.from({ length: 6 }, (_, i) => [`file-${i}:published`, `file-${i}:detached`]).flat(),
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
for (const point of ['removing:renamed', ...Array.from({ length: 6 }, (_, i) => `file-${i}:removed`), 'removed:renamed']) {
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

for (const [operation, point, expected, controller = false, client = false] of [
  ['install', 'prepared:dir-synced', 'installed'], ['install', 'file-0:published', 'installed'],
  ['install', 'file-2:detached', 'installed'], ['install', 'installed:dir-synced', 'installed'],
  ['install', 'file-5:published', 'installed'],
  ['remove', 'removing:dir-synced', 'removed'], ['remove', 'file-2:removed', 'removed'],
  ['remove', 'removed:dir-synced', 'removed'],
  ['remove', 'file-5:removed', 'removed'],
  ['install', 'file-6:published', 'installed', true], ['install', 'file-8:published', 'installed', true],
  ['install', 'file-9:detached', 'installed', true], ['remove', 'file-9:removed', 'removed', true],
  ['remove', 'file-6:removed', 'removed', true],
  ['install', 'file-10:published', 'installed', true, true], ['install', 'file-12:published', 'installed', true, true],
  ['remove', 'file-12:removed', 'removed', true, true], ['remove', 'file-10:removed', 'removed', true, true],
]) test(`actual SIGKILL under flock at ${point}`, async (t) => {
  const f = await fixture(t, controller, client); if (operation === 'remove') await f.run('install');
  const lock = join(f.root, 'deployment.lock');
  const script = `
    import { dnsDeploymentFiles } from ${JSON.stringify(new URL('./lib/dns-deployment-files.mjs', import.meta.url).href)};
    import { ownsBootGuardLock } from ${JSON.stringify(new URL('./lib/dns-boot-guard.mjs', import.meta.url).href)};
    import { readdir, readFile } from 'node:fs/promises';
    const o = JSON.parse(process.argv[1]), point = process.argv[2];
    for (const file of o.files) if (file.contents?.type === 'Buffer') file.contents = Buffer.from(file.contents.data);
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
    if (expected === 'installed') {
      assert.deepEqual(await readFile(f.target(i)), Buffer.from(file.contents)); assert.equal((await lstat(f.target(i))).nlink, 1);
    }
    else await absent(f.target(i));
  }
});
