import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdir, readFile, writeFile, lstat, readdir, rename, chmod } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { deploymentHarness } from './fixtures/dns-deployment-harness.mjs';
import { compileDnsClientDeploymentFiles, dnsClientDeploymentDescriptors } from './lib/dns-deployment-files.mjs';
import { readDnsDeployment, validateDnsDeployment } from './lib/dns-deployment.mjs';
import { runCommand } from './lib/transparent-acceptance.mjs';

function clientInput(bundle) {
  const domainPolicy = { schema: 1, denySuffixes: ['internal'] };
  return { bundle, secret: Buffer.alloc(32, 0x5a),
    adapter: { schema: 1, exitIp: '93.184.216.36', exitPort: 443, publicName: 'relay.example',
      listenPort: 1053, readyName: 'example.com', domainPolicy,
      upstream: { schema: 1, transport: 'doh', hostname: 'resolver.example', port: 443, path: '/dns-query',
        bootstrap: { addresses: ['93.184.216.35'] }, trust: { mode: 'bundled' } } },
    guard: { schema: 1, kind: 'clean-vpn-dns-boot-policy', enabled: true, firewallBackend: 'nf_tables',
      input: { schema: 1, client: 'vps2', id: 'a'.repeat(32) } },
    config: { schema: 1, kind: 'clean-vpn-dns-client', client: 'vps2', uplink: 'eth0',
      networkFile: { path: '/run/systemd/network/10-netplan-eth0.network', sha256: 'c'.repeat(64) },
      adapterPort: 1053, readyName: 'example.com', domainPolicy } };
}
async function fixture(t) {
  const setup = `const {compileDnsClientDeploymentFiles} = await import('/project/scripts/lib/dns-deployment-files.mjs');
    if (options.operation === 'install' || options.withInput) {
      options.files = compileDnsClientDeploymentFiles((${clientInput.toString()})(await readFile(options.source+'/bundle.json','utf8')));
    } else options.source = undefined;`;
  const f = await deploymentHarness(t, { moduleName: 'dns-deployment', entry: 'dnsDeployment', setup });
  const files = compileDnsClientDeploymentFiles(clientInput(await readFile(join(f.source, 'bundle.json'), 'utf8')));
  for (const file of files) await mkdir(dirname(join(f.root, file.path)), { recursive: true, mode: 0o700 });
  return { ...f, files, configPath: (i) => join(f.root, files[i].path) };
}
const absent = (path) => assert.rejects(lstat(path), { code: 'ENOENT' });
test('combined publication binds code and all 13 client files; inactive rollback retains code', async (t) => {
  const f = await fixture(t);
  const done = await f.ok('install', `if(point==='files:file-12:published') {
    const {lstat} = await import('node:fs/promises'); await lstat(options.root+'/opt/clean-vpn/bundle.json');
  }`);
  assert.equal(done.stage, 'installed'); assert.equal(done.activated, false);
  assert.deepEqual(await f.ok('inspect'), done); assert.deepEqual(await f.ok('recover'), done);
  const record = await readDnsDeployment(f.directory); assert.equal(record.files.length, 13);
  assert.equal(JSON.stringify(record).includes('contents'), false);
  assert.equal(JSON.stringify(record).includes(Buffer.alloc(32, 0x5a).toString('hex')), false);
  for (const [i, file] of f.files.entries()) assert.deepEqual(await readFile(f.configPath(i)), Buffer.from(file.contents));
  const removed = await f.ok('remove', `if(point==='code:bundle:before-move') {
    const {lstat} = await import('node:fs/promises');
    await assert.rejects(lstat(options.root+'/etc/clean-vpn/dns/client-opt-in.json'),{code:'ENOENT'});
  }`);
  assert.equal(removed.stage, 'removed'); assert.equal(removed.postActivationUninstall, false);
  await absent(f.target); for (const [i] of f.files.entries()) await absent(f.configPath(i));
  await lstat(join(f.directory, 'code/retired/bundle.json'));
  assert.deepEqual(await f.ok('recover'), removed); assert.notEqual((await f.run('install')).code, 0);
});
test('opt-in mismatch is refused before journal or code staging', async (t) => {
  const f = await fixture(t);
  assert.throws(() => dnsClientDeploymentDescriptors(f.files, 'f'.repeat(64)), /opt-in\/code bundle mismatch/);
  assert.notEqual((await f.run('install', '', { expectedSha256: 'f'.repeat(64) })).code, 0);
  assert.deepEqual(await readdir(f.directory), []); await absent(f.target);
});
test('caller cannot mutate sensitive plan while code publication is in flight', async (t) => {
  const f = await fixture(t);
  await f.ok('install', `if(point==='code:bundle:published') {
    options.files[10].contents.fill(0); options.files[11].contents='{}'; options.files[12].contents='{}';
  }`);
  assert.deepEqual(await readFile(f.configPath(10)), Buffer.alloc(32, 0x5a));
  assert.deepEqual(await readFile(f.configPath(11)), Buffer.from(f.files[11].contents));
});
test('full OS checks are bounded by visible operations, not code-file count or nested inventories', async (t) => {
  const f = await fixture(t), manifest = JSON.parse(await readFile(join(f.source, 'bundle.json'), 'utf8'));
  for (let i = 0; i < 64; i++) {
    const path = `scripts/lib/module-${i}.mjs`, body = `export const value = ${i};\n`;
    await writeFile(join(f.source, path), body, { mode: 0o644 }); await chmod(join(f.source, path), 0o644);
    manifest.files[path] = createHash('sha256').update(body).digest('hex');
  }
  const body = JSON.stringify(manifest); await writeFile(join(f.source, 'bundle.json'), body);
  f.options.expectedSha256 = createHash('sha256').update(body).digest('hex');
  const r = await f.ok('install', '', { countInactive: true });
  assert.ok(r.inactiveChecks >= 26 && r.inactiveChecks <= 60, `full inactivity checks: ${r.inactiveChecks}`);
});
for (const point of ['files:prepared:dir-synced', 'files:file-12:published'])
  test(`loss of inactivity at ${point} prevents next publication step`, async (t) => {
    const f = await fixture(t);
    assert.notEqual((await f.run('install', `if(point===${JSON.stringify(point)}) options.inactive=false;`)).code, 0);
    if (point === 'files:prepared:dir-synced') await absent(f.configPath(0));
    else assert.equal((await lstat(f.configPath(12))).nlink, 2, 'unapproved opt-in must not become a single-link authority file');
    assert.notEqual((await f.run('recover', '', { inactive: false })).code, 0);
  });
for (const kind of ['code', 'config', 'active', 'lock']) test(`combined removal refuses ${kind} drift before revoking anything`, async (t) => {
  const f = await fixture(t); await f.ok('install'); const opt = await readFile(f.configPath(12));
  if (kind === 'code') await writeFile(join(f.target, 'scripts/dns-client.mjs'), '// foreign\n');
  if (kind === 'config') await writeFile(f.configPath(0), 'foreign');
  assert.notEqual((await f.run('remove', '', { inactive: kind !== 'active', withoutLock: kind === 'lock' })).code, 0);
  assert.deepEqual(await readFile(f.configPath(12)), opt); await lstat(f.target);
  assert.equal((await readDnsDeployment(f.directory)).stage, 'installed');
});
test('changed code during file staging prevents publication of opt-in', async (t) => {
  const f = await fixture(t);
  assert.notEqual((await f.run('install', `if(point==='files:file-0:published') await writeFile(options.root+'/opt/clean-vpn/scripts/dns-client.mjs','// foreign');`)).code, 0);
  await absent(f.configPath(12)); assert.notEqual((await f.run('recover')).code, 0);
});
test('missing child journal with private staging is preserved for review, not adopted', async (t) => {
  const f = await fixture(t);
  assert.notEqual((await f.run('install', `if(point==='code:bundle:staged') throw new Error('CUT');`)).code, 0);
  assert.equal((await readDnsDeployment(f.directory)).stage, 'code');
  await absent(f.target); await lstat(join(f.directory, 'code/bundle/bundle.json'));
  assert.notEqual((await f.run('recover', '', { withInput: true })).code, 0);
  assert.notEqual((await f.run('remove')).code, 0);
});
test('completed code and no client journal can roll back without sensitive inputs', async (t) => {
  const f = await fixture(t);
  assert.notEqual((await f.run('install', `if(point==='files:dir-synced') throw new Error('CUT');`)).code, 0);
  assert.equal((await readDnsDeployment(f.directory)).stage, 'files');
  assert.equal((await f.ok('remove')).stage, 'removed'); await absent(f.target);
});
test('child identity and metadata are bound, not a permission to adopt matching foreign journals', async (t) => {
  const f = await fixture(t); await f.ok('install');
  await rename(join(f.directory, 'files'), join(f.directory, 'saved-files')); await mkdir(join(f.directory, 'files'), { mode: 0o700 });
  assert.notEqual((await f.run('remove')).code, 0); await lstat(f.configPath(12));
  const record = await readDnsDeployment(f.directory);
  for (const mutate of [(v) => { v.stage = 'active'; }, (v) => { v.files.pop(); },
    (v) => { v.files[0].path = '/etc/resolv.conf'; }, (v) => { v.secret = 'unexpected'; }]) {
    const v = structuredClone(record); mutate(v); assert.throws(() => validateDnsDeployment(v));
  }
});

for (const [operation, point, expected] of [
  ['install', 'code:prepared:dir-synced', 'installed'],
  ['install', 'code:bundle:published', 'installed'],
  ['install', 'files:prepared:dir-synced', 'installed'],
  ['install', 'files:file-12:published', 'installed'],
  ['remove', 'files:file-12:removed', 'removed'],
  ['remove', 'removing-code:dir-synced', 'removed'],
  ['remove', 'code:bundle:retired', 'removed'],
]) test(`real process SIGKILL resumes only recorded direction at ${point}`, async (t) => {
  const f = await fixture(t); if (operation === 'remove') await f.ok('install');
  const child = spawn('/usr/bin/unshare', f.args(operation,
    `if(point===${JSON.stringify(point)}) {process.stdout.write('CUT\\n'); await new Promise(()=>setInterval(()=>{},1000));}`), { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = ''; child.stdout.on('data', (b) => { out += b; }); child.stderr.on('data', (b) => { err += b; });
  const closed = once(child, 'close'); const timer = setTimeout(() => child.kill('SIGKILL'), 20000);
  try {
    await new Promise((resolve, reject) => {
      const check = () => { if (out.includes('CUT\n')) resolve(); };
      child.stdout.on('data', check); check(); child.once('close', () => reject(new Error(`no checkpoint: ${err}`)));
    });
    assert.equal((await runCommand('/usr/bin/flock', ['-n', '-E', '75', f.lock, '/usr/bin/true'])).code, 75);
    child.kill('SIGKILL'); assert.deepEqual(await closed, [null, 'SIGKILL']);
  } finally { clearTimeout(timer); if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await closed; }
  // Early code cuts need the original client input to stage files, but cuts
  // after its journal is durable do not need the key/config or original source.
  const withInput = point.startsWith('code:') && operation === 'install';
  const r = await f.ok('recover', '', { withInput }); assert.equal(r.stage, expected);
  if (expected === 'removed') { await absent(f.target); await absent(f.configPath(12)); }
  else await lstat(f.configPath(12));
});
