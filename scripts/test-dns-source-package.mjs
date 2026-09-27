import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, writeFile, readFile, stat, symlink, link, rm, readdir, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { packageDnsSource } from './lib/dns-source-package.mjs';
import { inspectDnsInstalledBundle } from './lib/dns-installed-authority.mjs';
import { parseDnsSourcePackageArgs } from './dns-source-package.mjs';

async function fixture(t) {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'meshpn-dns-package-')));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const source = join(directory, 'source'), output = join(directory, 'output');
  await mkdir(join(source, 'scripts/lib'), { recursive: true });
  await writeFile(join(source, 'scripts/dns-client.mjs'), 'export const client = true;\n');
  await writeFile(join(source, 'scripts/lib/dns-installed-authority.mjs'), 'export const authority = true;\n');
  await writeFile(join(source, 'scripts/lib/example.js'), 'module.exports = 1;\n');
  return { source, output, directory };
}
test('offline package has exact public code inventory and deterministic manifest, not config or credentials', async (t) => {
  const f = await fixture(t);
  await writeFile(join(f.source, 'scripts/private.key'), 'do not copy');
  await writeFile(join(f.source, 'scripts/settings.json'), '{"secret":"do not copy"}');
  const report = await packageDnsSource(f);
  assert.equal(report.files, 3); assert.equal(report.installationPerformed, false);
  assert.equal(report.systemSettingsChanged, false); assert.equal(report.dnsQueriesSent, 0);
  const first = await readFile(join(f.output, 'bundle.json'));
  assert.equal(report.bundleSha256, createHash('sha256').update(first).digest('hex'));
  assert.equal((await inspectDnsInstalledBundle(f.output, process.getuid())).sha256, report.bundleSha256);
  assert.deepEqual((await readdir(join(f.output, 'scripts'))).sort(), ['dns-client.mjs', 'lib']);
  for (const p of ['', 'scripts', 'scripts/lib']) assert.equal((await stat(join(f.output, p))).mode & 0o7777, 0o755);
  for (const p of ['bundle.json', 'scripts/dns-client.mjs', 'scripts/lib/dns-installed-authority.mjs', 'scripts/lib/example.js'])
    assert.equal((await stat(join(f.output, p))).mode & 0o7777, 0o644);
  const second = await packageDnsSource({ source: f.source, output: join(f.directory, 'second') });
  assert.equal(second.bundleSha256, report.bundleSha256);
  await writeFile(join(f.source, 'scripts/lib/example.js'), 'module.exports = 2;\n');
  const third = await packageDnsSource({ source: f.source, output: join(f.directory, 'third') });
  assert.notEqual(third.bundleSha256, report.bundleSha256);
  assert.equal(await readFile(join(f.output, 'scripts/lib/example.js'), 'utf8'), 'module.exports = 1;\n');
});
test('existing destination and destination inside source are refused without overwrite', async (t) => {
  const f = await fixture(t); await mkdir(f.output); await writeFile(join(f.output, 'keep'), 'original');
  await assert.rejects(packageDnsSource(f), { code: 'EEXIST' });
  assert.deepEqual(await readdir(f.output), ['keep']);
  assert.equal(await readFile(join(f.output, 'keep'), 'utf8'), 'original');
  await assert.rejects(packageDnsSource({ source: f.source, output: join(f.source, 'package') }), /outside source/);
  await assert.rejects(stat(join(f.source, 'package')), { code: 'ENOENT' });
});
for (const kind of ['file-symlink', 'directory-symlink', 'hardlink', 'empty', 'oversized', 'bad-name', 'missing-entry'])
  test(`invalid source ${kind} fails before creating a package`, async (t) => {
    const f = await fixture(t), path = join(f.source, 'scripts/dns-client.mjs');
    if (kind === 'file-symlink') await symlink(path, join(f.source, 'scripts/linked.mjs'));
    if (kind === 'directory-symlink') await symlink(join(f.source, 'scripts/lib'), join(f.source, 'scripts/linked'));
    if (kind === 'hardlink') await link(path, join(f.source, 'scripts/linked.mjs'));
    if (kind === 'empty') await writeFile(path, '');
    if (kind === 'oversized') await writeFile(path, Buffer.alloc(1048577));
    if (kind === 'bad-name') await writeFile(join(f.source, 'scripts/bad name.js'), 'x');
    if (kind === 'missing-entry') await rm(path);
    await assert.rejects(packageDnsSource(f)); await assert.rejects(stat(f.output), { code: 'ENOENT' });
  });
test('package refuses a symlinked output parent and relative path spellings', async (t) => {
  const f = await fixture(t); await symlink(f.directory, join(f.directory, 'linked'));
  await assert.rejects(packageDnsSource({ source: f.source, output: join(f.directory, 'linked/output') }));
  await assert.rejects(packageDnsSource({ source: f.source, output: 'relative' }));
  await assert.rejects(packageDnsSource({ source: `${f.source}/.`, output: f.output }));
  await assert.rejects(stat(f.output), { code: 'ENOENT' });
});
test('package arguments accept exactly one new absolute output or help', () => {
  assert.equal(parseDnsSourcePackageArgs(['--help']), null);
  assert.equal(parseDnsSourcePackageArgs(['--output=/tmp/example']), '/tmp/example');
  for (const args of [[], ['--install'], ['--output=relative'], ['--output=/'], ['--output=/tmp/../etc'],
    ['--output=/tmp/example', '--output=/tmp/other'], ['--help', '--install']]) assert.throws(() => parseDnsSourcePackageArgs(args));
});
