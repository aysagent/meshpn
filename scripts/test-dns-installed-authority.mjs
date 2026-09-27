import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, writeFile, readFile, chmod, rm, rename, symlink, link, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { runCommand } from './lib/transparent-acceptance.mjs';
import { parseDnsClientArgs, dnsClientFailureLocation } from './dns-client.mjs';
import { validateDnsClientOptIn, validateDnsInstalledBundle, inspectDnsInstalledBundle,
  loadDnsInstalledAuthority, assertDnsInstalledAuthority, dnsInstalledAuthorityInfo } from './lib/dns-installed-authority.mjs';

const self = 'scripts/lib/dns-installed-authority.mjs';
const entry = 'scripts/dns-client.mjs';
const hash = (s) => createHash('sha256').update(s).digest('hex');
const opt = (client = 'vps2') => ({ schema: 1, kind: 'clean-vpn-dns-client-opt-in', enabled: true,
  client, guardId: 'a'.repeat(32), bundleSha256: 'b'.repeat(64), configSha256: 'c'.repeat(64) });
test('explicit client opt-in is separate from boot protection and binds both code and configuration', () => {
  for (const client of ['vps2', 'radxa']) assert.deepEqual(validateDnsClientOptIn(opt(client)), opt(client));
  for (const changes of [{ enabled: false }, { enabled: 'true' }, { client: 'vps1' }, { schema: 2 },
    { guardId: 'x'.repeat(32) }, { bundleSha256: '' }, { configSha256: null }, { extra: true }, { kind: 'clean-vpn-dns-boot-policy' }])
    assert.throws(() => validateDnsClientOptIn({ ...opt(), ...changes }));
  for (const field of Object.keys(opt())) { const v = opt(); delete v[field]; assert.throws(() => validateDnsClientOptIn(v)); }
});
test('bundle format refuses paths outside installed code, traversal, missing gate and excessive inventory', () => {
  const base = { schema: 1, kind: 'clean-vpn-dns-code-bundle', files: { [self]: hash('module'), [entry]: hash('entry') } };
  assert.deepEqual(validateDnsInstalledBundle(base), base);
  for (const path of ['/etc/resolv.conf', '../scripts/x.mjs', 'scripts/../x.mjs', 'scripts/a//b.mjs',
    'scripts/.hidden.mjs', 'scripts/a.pem', 'scripts/a.mjs\n', '__proto__'])
    assert.throws(() => validateDnsInstalledBundle({ ...base, files: { ...base.files, [path]: hash('x') } }));
  assert.throws(() => validateDnsInstalledBundle({ ...base, files: {} }));
  assert.throws(() => validateDnsInstalledBundle({ ...base, files: { 'scripts/a.mjs': hash('x') } }));
  assert.throws(() => validateDnsInstalledBundle({ ...base, files: { [self]: hash('module') } }));
  assert.throws(() => validateDnsInstalledBundle({ ...base, files: { [self]: 'unknown' } }));
  const files = { ...base.files }; for (let i = 0; i < 512; i++) files[`scripts/x${i}.mjs`] = hash('x');
  assert.throws(() => validateDnsInstalledBundle({ ...base, files }));
});
async function fixture(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'meshpn-dns-installed-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'scripts/lib'), { recursive: true });
  for (const path of ['', 'scripts', 'scripts/lib']) await chmod(join(root, path), 0o755);
  const contents = { [self]: 'export const fixture = true;\n', [entry]: 'import "./lib/dns-installed-authority.mjs";\n' };
  for (const [path, data] of Object.entries(contents)) { await writeFile(join(root, path), data); await chmod(join(root, path), 0o644); }
  const body = JSON.stringify({ schema: 1, kind: 'clean-vpn-dns-code-bundle', files: Object.fromEntries(Object.entries(contents).map(([k, v]) => [k, hash(v)])) });
  await writeFile(join(root, 'bundle.json'), body); await chmod(join(root, 'bundle.json'), 0o644);
  return { root, body, inspect: () => inspectDnsInstalledBundle(root, process.getuid()), path: (p) => join(root, p) };
}
test('real private-root inventory is read-only, complete, content-checked, and cannot mint authority', async (t) => {
  const f = await fixture(t), before = await readFile(f.path('bundle.json'));
  const first = await f.inspect(); assert.equal(first.sha256, hash(f.body));
  assert.deepEqual(Object.keys(first.files).sort(), [entry, self].sort());
  assert.deepEqual(await f.inspect(), first); assert.deepEqual(await readFile(f.path('bundle.json')), before);
  await assert.rejects(assertDnsInstalledAuthority(first), /token required/);
  assert.throws(() => dnsInstalledAuthorityInfo(first), /token required/);
});
for (const [name, mutate] of [
  ['wrong bytes', async (f) => writeFile(f.path(self), 'other')],
  ['missing file', async (f) => rm(f.path(self))],
  ['unlisted file', async (f) => writeFile(f.path('scripts/extra.mjs'), 'x')],
  ['writable code', async (f) => chmod(f.path(self), 0o666)],
  ['executable code', async (f) => chmod(f.path(self), 0o755)],
  ['writable directory', async (f) => chmod(f.path('scripts/lib'), 0o777)],
  ['private code directory', async (f) => chmod(f.path('scripts/lib'), 0o700)],
  ['writable manifest', async (f) => chmod(f.path('bundle.json'), 0o666)],
  ['malformed manifest', async (f) => writeFile(f.path('bundle.json'), '{')],
  ['non-UTF8 manifest', async (f) => writeFile(f.path('bundle.json'), Buffer.from([255]))],
  ['oversized manifest', async (f) => writeFile(f.path('bundle.json'), 'x'.repeat(131073))],
  ['oversized code', async (f) => writeFile(f.path(self), 'x'.repeat(1048577))],
  ['symlink code', async (f) => { await rename(f.path(self), f.path('saved')); await symlink('../../saved', f.path(self)); }],
  ['hardlink code', async (f) => link(f.path(self), f.path('saved'))],
  ['symlink manifest', async (f) => { await rename(f.path('bundle.json'), f.path('saved')); await symlink('saved', f.path('bundle.json')); }],
  ['symlink code directory', async (f) => { await rename(f.path('scripts/lib'), f.path('saved')); await symlink('../saved', f.path('scripts/lib')); }],
]) test(`installed bundle refuses ${name} without repairing files`, async (t) => {
  const f = await fixture(t); await mutate(f); await assert.rejects(f.inspect());
});
test('inventory refuses another owner; ordinary repo execution and fake tokens grant no authority', async (t) => {
  const f = await fixture(t);
  await assert.rejects(inspectDnsInstalledBundle(f.root, process.getuid() + 1));
  await assert.rejects(loadDnsInstalledAuthority());
  for (const token of [{}, null, opt(), Object.freeze({ client: 'vps2' })]) {
    await assert.rejects(assertDnsInstalledAuthority(token), /token required/);
    assert.throws(() => dnsInstalledAuthorityInfo(token), /token required/);
  }
});
test('installed bundle bounds total code bytes, not only each file', async (t) => {
  const f = await fixture(t), manifest = JSON.parse(f.body), bytes = Buffer.alloc(1024 * 1024, 120), digest = hash(bytes);
  for (let i = 0; i < 17; i++) {
    const path = `scripts/large${i}.mjs`; await writeFile(f.path(path), bytes); await chmod(f.path(path), 0o644); manifest.files[path] = digest;
  }
  await writeFile(f.path('bundle.json'), JSON.stringify(manifest));
  await assert.rejects(f.inspect(), /bundle total size limit/);
});
test('installed CLI requires one explicit supported operation and rejects installer or ambiguous arguments', () => {
  assert.equal(parseDnsClientArgs(['--help']), 'help'); assert.equal(parseDnsClientArgs(['--inspect']), 'inspect');
  assert.equal(parseDnsClientArgs(['--start']), 'start'); assert.equal(parseDnsClientArgs(['--disable']), 'disable');
  for (const args of [[], ['--apply'], ['--install'], ['--inspect', '--help'],
    ['--inspect', '--inspect'], ['--inspect=true'], ['--root=/tmp'], ['--client=radxa']])
    assert.throws(() => parseDnsClientArgs(args), { code: 'DNS_CLIENT_ARGUMENTS' });
});
test('installed CLI help is offline; ordinary repo inspection fails with a redacted result', async () => {
  const path = new URL('./dns-client.mjs', import.meta.url).pathname;
  const help = await runCommand(process.execPath, [path, '--help']);
  assert.equal(help.code, 0); assert.match(help.stdout, /Inspection changes no settings/); assert.equal(help.stderr, '');
  assert.match(help.stdout, /--probe-adapter sends four protected DNS queries/);
  for (const [arg, expected] of [['--inspect', 'DNS_CLIENT_REFUSED'], ['--probe-adapter', 'DNS_CLIENT_REFUSED'], ['--start', 'DNS_CLIENT_REFUSED'], ['--disable', 'DNS_CLIENT_REFUSED']]) {
    const r = await runCommand(process.execPath, [path, arg]);
    assert.equal(r.code, 1); assert.equal(r.stdout, ''); assert.equal(r.stderr.trim(), expected);
  }
});
test('installed refusal location omits message, absolute path and other stack frames', () => {
  const e = new Error('secret configuration value');
  e.stack = 'Error: secret configuration value\n    at private (file:///secret/private.mjs:1:1)\n    at check (file:///opt/clean-vpn/scripts/lib/dns-installed-vps2.mjs:42:12)';
  assert.equal(dnsClientFailureLocation(e), 'dns-installed-vps2.mjs:42');
  assert.equal(dnsClientFailureLocation({ stack: e.stack }), null);
  for (const frame of ['file:///opt/clean-vpn/scripts/lib/unknown.mjs:42:12', 'file:///tmp/dns-installed-vps2.mjs:42:12',
    'file:///opt/clean-vpn/scripts/lib/dns-installed-vps2.mjs:9999999:12']) {
    e.stack = `Error: secret\n    at check (${frame})`; assert.equal(dnsClientFailureLocation(e), null);
  }
});
