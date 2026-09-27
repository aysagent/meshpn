/** File-only part of the opt-in installer. Caller holds its deployment lock and
 * proves services/boot dependencies have NOT been activated. No service calls,
 * DNS setters, directory creation or source-code installation. Credentials in
 * the explicit client set remain private; the journal contains only hashes. */
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { open, lstat, realpath, link, unlink, readdir, readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { compileDnsAdapterServicePlan } from './dns-adapter-service-plan.mjs';
import { compileDnsControllerServicePlan } from './dns-controller-service-plan.mjs';
import { validateDnsBootPolicy, dnsBootGuardUnit } from './dns-boot-guard.mjs';
import { privateJournalDirectory, readPrivateJournal, writePrivateJournal, syncDirectory } from './dns-lifecycle-journal.mjs';
import { DNS_NETWORKD_POLICY, DNS_NETWORKD_CONTENTS, dnsNetworkdPolicyArtifact } from './dns-networkd-policy.mjs';
import { validateDnsClientOptIn, validateDnsInstalledBundle } from './dns-installed-authority.mjs';
import { validateVps2DnsConfig } from './dns-vps2-baseline.mjs';
import { assessLoadedDnsAdapter } from './dns-installed-adapter.mjs';

const paths = new Map([
  ['/etc/systemd/system/clean-vpn-dns-adapter.service', '0644'],
  ['/etc/clean-vpn/dns/upstream.json', '0600'],
  ['/etc/clean-vpn/dns/domains.json', '0600'],
  ['/etc/systemd/system/clean-vpn-dns-guard.service', '0644'],
  ['/etc/clean-vpn/dns/guard-policy.json', '0600'],
  [DNS_NETWORKD_POLICY, '0644'],
]);
const basePaths = [...paths.keys()].filter((p) => p !== DNS_NETWORKD_POLICY);
const controllerPlans = ['legacy', 'nf_tables'].map((firewallBackend) =>
  compileDnsControllerServicePlan({ schema: 1, client: 'vps2', firewallBackend }).files);
const controllerPaths = controllerPlans[0].map((f) => f.path);
for (const path of controllerPaths) paths.set(path, '0644');
const privatePaths = ['/etc/clean-vpn/dns/hmac.key', '/etc/clean-vpn/dns/client.json', '/etc/clean-vpn/dns/client-opt-in.json'];
// Fixed boundary, not a caller-selected path or arbitrary partial deletion.
const dependencyBoundary = controllerPaths[2];
for (const path of privatePaths) paths.set(path, '0600');
function selectedPaths(files) {
  assert.ok(Array.isArray(files));
  const selected = files.map((f) => f.path);
  const controller = selected.some((p) => controllerPaths.includes(p));
  const client = selected.some((p) => privatePaths.includes(p));
  if (client) {
    // The opt-in is published LAST and removed FIRST, never while another
    // member of the initial file set is missing. Old sets keep their order.
    assert.deepEqual(selected, [...basePaths, DNS_NETWORKD_POLICY, ...controllerPaths, ...privatePaths]);
  }
  assert.deepEqual([...selected].sort(), [...basePaths,
    ...(controller || selected.includes(DNS_NETWORKD_POLICY) ? [DNS_NETWORKD_POLICY] : []),
    ...(controller ? controllerPaths : []), ...(client ? privatePaths : [])].sort());
  // A new controller group must be complete and match ONE reviewed backend,
  // including both manager drop-ins. No arbitrary unit payload or mixed pair.
  if (controller) assert.ok(controllerPlans.some((plan) => plan.every((f) =>
    files.find((v) => v.path === f.path)?.sha256 === f.sha256)), 'unreviewed controller artifacts');
  return selected;
}
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const keys = (v, names) => {
  assert.ok(v && typeof v === 'object' && !Array.isArray(v));
  assert.deepEqual(Object.keys(v).sort(), [...names].sort());
};
export function compileDnsDeploymentFiles({ adapter, guard, controller = false }) {
  const plan = compileDnsAdapterServicePlan(adapter); validateDnsBootPolicy(guard);
  assert.equal(typeof controller, 'boolean');
  if (controller) assert.equal(guard.input.client, 'vps2', 'installed controller is VPS2-only');
  return [...plan.files,
    { path: '/etc/systemd/system/clean-vpn-dns-guard.service', mode: '0644', contents: dnsBootGuardUnit(guard.firewallBackend) },
    { path: '/etc/clean-vpn/dns/guard-policy.json', mode: '0600', contents: `${JSON.stringify(guard)}\n` },
    ...(guard.input.client === 'vps2' ? [dnsNetworkdPolicyArtifact()] : []),
    ...(controller ? compileDnsControllerServicePlan({ schema: 1, client: 'vps2', firewallBackend: guard.firewallBackend }).files : []),
  ].map((f) => ({ ...f, sha256: hash(f.contents) }));
}
/** Explicit sensitive file set, NOT a printable plan or a live authorization.
 * Caller must independently verify/publish the approved code bundle before
 * installing this set, and hold the deployment lock with real inactive proof.
 * This function neither reads nor generates a key; secret is an existing PSK. */
export function compileDnsClientDeploymentFiles({ adapter, guard, config, bundle, secret }) {
  validateVps2DnsConfig(config);
  assert.equal(typeof bundle, 'string'); assert.ok(Buffer.byteLength(bundle) <= 131072);
  validateDnsInstalledBundle(JSON.parse(bundle));
  assert.ok(Buffer.isBuffer(secret) && secret.length === 32, '32-byte binary PSK required');
  const files = compileDnsDeploymentFiles({ adapter, guard, controller: true });
  const contents = `${JSON.stringify(config)}\n`;
  const permit = validateDnsClientOptIn({ schema: 1, kind: 'clean-vpn-dns-client-opt-in', enabled: true,
    client: 'vps2', guardId: guard.input.id, bundleSha256: hash(bundle), configSha256: hash(contents) });
  const extra = [Buffer.from(secret), contents, `${JSON.stringify(permit)}\n`];
  for (const [i, path] of privatePaths.entries()) files.push({ path, mode: '0600', contents: extra[i], sha256: hash(extra[i]) });
  try { return validateFiles(files); }
  catch (error) { extra[0].fill(0); throw error; }
}
function validateFiles(files) {
  selectedPaths(files);
  for (const f of files) {
    keys(f, ['path', 'mode', 'contents', 'sha256']);
    assert.equal(f.mode, paths.get(f.path));
    if (f.path === privatePaths[0]) assert.ok(Buffer.isBuffer(f.contents) && f.contents.length === 32, '32-byte binary PSK required');
    else assert.equal(typeof f.contents, 'string');
    assert.ok(Buffer.byteLength(f.contents) > 0 && Buffer.byteLength(f.contents) <= 131072);
    assert.equal(f.sha256, hash(f.contents));
    if (f.path === DNS_NETWORKD_POLICY) assert.equal(f.contents, DNS_NETWORKD_CONTENTS);
  }
  if (files.some((f) => controllerPaths.includes(f.path))) {
    const policy = validateDnsBootPolicy(JSON.parse(files.find((f) => f.path === '/etc/clean-vpn/dns/guard-policy.json').contents));
    assert.equal(policy.input.client, 'vps2');
    const expected = compileDnsControllerServicePlan({ schema: 1, client: 'vps2', firewallBackend: policy.firewallBackend }).files;
    for (const f of expected) assert.equal(files.find((v) => v.path === f.path).sha256, f.sha256, 'controller/guard backend mismatch');
  }
  if (files.some((f) => privatePaths.includes(f.path))) {
    const get = (path) => files.find((v) => v.path === path).contents;
    const config = validateVps2DnsConfig(JSON.parse(get(privatePaths[1])));
    assert.ok(Buffer.byteLength(get(privatePaths[1])) <= 65536 && Buffer.byteLength(get(privatePaths[2])) <= 2048);
    const permit = validateDnsClientOptIn(JSON.parse(get(privatePaths[2])));
    const guard = validateDnsBootPolicy(JSON.parse(get('/etc/clean-vpn/dns/guard-policy.json')));
    assert.equal(permit.client, config.client); assert.equal(permit.client, guard.input.client);
    assert.equal(permit.guardId, guard.input.id); assert.equal(permit.configSha256, hash(get(privatePaths[1])));
    const unitText = get('/etc/systemd/system/clean-vpn-dns-adapter.service');
    const starts = [...unitText.matchAll(/^ExecStart=(.+)$/gm)]; assert.equal(starts.length, 1);
    // Reuse the strict loaded-template assessment: rejects arbitrary commands,
    // a wrong listener/readiness name, or differing private domain policy.
    assessLoadedDnsAdapter({ config, unitText,
      argv: starts[0][1].replaceAll('${CREDENTIALS_DIRECTORY}', '/run/credentials/clean-vpn-dns-adapter.service').split(' '),
      environment: ['CREDENTIALS_DIRECTORY=/run/credentials/clean-vpn-dns-adapter.service'],
      upstream: JSON.parse(get('/etc/clean-vpn/dns/upstream.json')),
      domainPolicy: JSON.parse(get('/etc/clean-vpn/dns/domains.json')) });
  }
  return files;
}
// Metadata-only binding for the enclosing code/config publication transaction.
// Validate sensitive contents before returning descriptors; never serialize keys.
export function dnsClientDeploymentDescriptors(files, bundleSha256) {
  validateFiles(files); assert.match(bundleSha256, /^[a-f0-9]{64}$/);
  assert.equal(files.length, 13); assert.equal(files.at(-1).path, privatePaths[2]);
  assert.equal(JSON.parse(files.at(-1).contents).bundleSha256, bundleSha256, 'opt-in/code bundle mismatch');
  return validateDnsClientDeploymentDescriptors(files.map(({ path, mode, sha256 }) => ({ path, mode, sha256 })));
}
export function validateDnsClientDeploymentDescriptors(files) {
  assert.equal(files.length, 13); selectedPaths(files);
  for (const f of files) {
    keys(f, ['path', 'mode', 'sha256']); assert.equal(f.mode, paths.get(f.path));
    assert.match(f.sha256, /^[a-f0-9]{64}$/);
    if (f.path === DNS_NETWORKD_POLICY) assert.equal(f.sha256, dnsNetworkdPolicyArtifact().sha256);
  }
  return files;
}
export function validateDnsDeploymentJournal(r) {
  keys(r, ['schema', 'backend', 'id', 'root', 'rootIdentity', 'directoryIdentity', 'parents', 'stage', 'files']);
  assert.equal(r.schema, 1); assert.equal(r.backend, 'dns-deployment-files');
  assert.match(r.id, /^[a-f0-9]{32}$/); assert.equal(resolve(r.root), r.root);
  assert.match(r.rootIdentity, /^\d+:\d+$/);
  assert.match(r.directoryIdentity, /^\d+:\d+$/);
  assert.ok(Array.isArray(r.parents));
  assert.deepEqual(r.parents.map((p) => p.path), parentPaths(selectedPaths(r.files)));
  for (const p of r.parents) { keys(p, ['path', 'identity']); assert.match(p.identity, /^\d+:\d+$/); }
  assert.ok(['installing', 'installed', 'detaching', 'detached', 'removing', 'removed'].includes(r.stage));
  if (['detaching', 'detached'].includes(r.stage)) {
    validateDnsClientDeploymentDescriptors(r.files.map(({ path, mode, sha256 }) => ({ path, mode, sha256 })));
    assert.equal(r.files[8].path, dependencyBoundary);
  }
  for (const f of r.files) {
    keys(f, ['path', 'mode', 'sha256', 'identity', 'mtimeNs']);
    assert.equal(f.mode, paths.get(f.path)); assert.match(f.sha256, /^[a-f0-9]{64}$/);
    assert.match(f.identity, /^\d+:\d+$/); assert.match(f.mtimeNs, /^\d+$/);
    if (f.path === DNS_NETWORKD_POLICY) assert.equal(f.sha256, dnsNetworkdPolicyArtifact().sha256);
  }
  return r;
}
export const readDnsDeploymentJournal = (directory) => readPrivateJournal(directory, validateDnsDeploymentJournal, 8192);
const maybe = async (action) => { try { return await action(); } catch (e) { if (e.code === 'ENOENT') return null; throw e; } };
const identity = (s) => `${s.dev}:${s.ino}`;
async function mountIdentity(path) {
  const fd = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const match = /^mnt_id:\s+(\d+)$/m.exec(await readFile(`/proc/self/fdinfo/${fd.fd}`, 'utf8'));
    assert.ok(match, 'deployment mount identity unavailable');
    assert.equal(identity(await fd.stat({ bigint: true })), identity(await lstat(path, { bigint: true })));
    return match[1];
  } finally { await fd.close(); }
}
function parentPaths(selected) {
  const result = new Set();
  for (const path of selected) {
    let current = '';
    for (const part of dirname(path).split('/').filter(Boolean)) { current += `/${part}`; result.add(current); }
  }
  return [...result].sort();
}

// Five legacy/Radxa artifacts, plus VPS2 exclusion and optional full controller
// group (ten files), or explicit credentials/config/opt-in (thirteen). Old
// journals are never implicitly upgraded. The future
// live entrypoint must validate root ownership, code, authorization and lock.
// Tests use a private root; importing the module has no filesystem effects.
export async function dnsDeploymentFiles({ root, directory, operation, files, assertInactive, checkpoint = async () => {} }) {
  // Own only a private copy of the caller's key; wipe it on success AND failure.
  // The caller remains responsible for disposing its original sensitive plan.
  if (operation === 'install') files = validateFiles(files).map((f) => ({ ...f,
    contents: Buffer.isBuffer(f.contents) ? Buffer.from(f.contents) : f.contents }));
  try { return await applyFiles({ root, directory, operation, files, assertInactive, checkpoint }); }
  finally { if (operation === 'install') for (const f of files) if (Buffer.isBuffer(f.contents)) f.contents.fill(0); }
}
async function applyFiles({ root, directory, operation, files, assertInactive, checkpoint }) {
  assert.ok(['install', 'recover', 'detach', 'remove', 'inspect'].includes(operation));
  assert.equal(typeof assertInactive, 'function', 'inactive deployment proof required');
  assert.equal(resolve(root), root); assert.equal(resolve(directory), directory);
  assert.equal(await realpath(root), root); assert.equal(await realpath(directory), directory);
  await privateJournalDirectory(directory);
  assert.equal(await assertInactive(), true, 'inactive deployment proof required');
  let record;
  if (operation !== 'install') record = await readDnsDeploymentJournal(directory);
  const selected = selectedPaths(record?.files ?? files);
  const rootStat = await lstat(root, { bigint: true });
  assert.ok(rootStat.isDirectory() && rootStat.uid === BigInt(process.getuid()) && !(rootStat.mode & 0o022n));
  const rootIdentity = identity(rootStat);
  const directoryIdentity = identity(await lstat(directory, { bigint: true }));
  const destination = (path) => join(root, path);
  const parent = async (path) => {
    // Walk EVERY component, not only a resolved leaf: no intermediate symlink
    // or writable system/config directory is trusted.
    let current = root;
    for (const part of dirname(path).split('/').filter(Boolean)) {
      current = join(current, part); const s = await lstat(current, { bigint: true });
      assert.ok(s.isDirectory() && !s.isSymbolicLink() && s.uid === BigInt(process.getuid()) && !(s.mode & 0o022n), 'untrusted deployment parent');
    }
    return current;
  };
  let parents;
  const context = async (checkInactive = false) => {
    await privateJournalDirectory(directory);
    assert.equal(await realpath(directory), directory);
    assert.equal(identity(await lstat(directory, { bigint: true })), directoryIdentity, 'journal directory changed');
    assert.equal(await realpath(root), root); assert.equal(identity(await lstat(root, { bigint: true })), rootIdentity);
    if (checkInactive) assert.equal(await assertInactive(), true, 'inactive deployment proof required');
    const mount = await mountIdentity(directory);
    for (const path of selected) {
      const targetParent = await parent(path);
      // Hardlinks cannot cross bind mounts, even on the same st_dev. Recheck
      // before publication/removal; reject fresh installs before staging.
      assert.equal(await mountIdentity(targetParent), mount, 'cross-mount deployment unsupported');
    }
    const current = await Promise.all(parentPaths(selected).map(async (path) => ({ path, identity: identity(await lstat(destination(path), { bigint: true })) })));
    if (parents) assert.deepEqual(current, parents, 'deployment parents changed'); else parents = current;
  };
  await context();
  if (operation === 'install') {
    assert.deepEqual(await readdir(directory), [], 'fresh deployment journal directory required');
    for (const f of files) assert.equal(await maybe(() => lstat(destination(f.path))), null, 'deployment target already exists');
    // Stage adjacent to the journal, fsync before publishing any target.
    // context() has already proved the SAME mount, not just device number.
    const entries = [];
    for (const [i, f] of files.entries()) {
      await context();
      const fd = await open(join(directory, `file-${i}`), 'wx', Number.parseInt(f.mode, 8));
      try {
        await fd.chmod(Number.parseInt(f.mode, 8)); await fd.writeFile(f.contents); await fd.sync();
        const s = await fd.stat({ bigint: true });
        entries.push({ path: f.path, mode: f.mode, sha256: f.sha256, identity: identity(s), mtimeNs: String(s.mtimeNs) });
      } finally { await fd.close(); }
    }
    await syncDirectory(directory);
    record = { schema: 1, backend: 'dns-deployment-files', id: randomBytes(16).toString('hex'), root, rootIdentity,
      directoryIdentity, parents, stage: 'installing', files: entries };
    await writePrivateJournal(directory, record, validateDnsDeploymentJournal, checkpoint, 8192, 'prepared');
  }
  assert.equal(record.root, root); assert.equal(record.rootIdentity, rootIdentity, 'deployment root changed');
  assert.equal(record.directoryIdentity, directoryIdentity, 'deployment journal moved');
  assert.deepEqual(record.parents, parents, 'deployment parent context changed');
  if (operation === 'detach') {
    assert.ok(['installed', 'detaching', 'detached'].includes(record.stage), 'detach requires a complete client deployment');
    validateDnsClientDeploymentDescriptors(record.files.map(({ path, mode, sha256 }) => ({ path, mode, sha256 })));
    assert.equal(record.files[8].path, dependencyBoundary);
  }
  const save = async (stage) => {
    record = { ...record, stage }; await writePrivateJournal(directory, record, validateDnsDeploymentJournal, checkpoint, 8192, stage);
  };
  const inspect = async (path, f) => maybe(async () => {
    const fd = await open(path, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
    let bytes;
    try {
      const s = await fd.stat({ bigint: true });
      assert.ok(s.isFile() && s.uid === BigInt(process.getuid()) && [1n, 2n].includes(s.nlink));
      assert.equal(identity(s), f.identity, 'foreign deployment inode');
      assert.equal(s.mode & 0o7777n, BigInt(Number.parseInt(f.mode, 8))); assert.equal(String(s.mtimeNs), f.mtimeNs);
      assert.ok(s.size > 0n && s.size <= 131072n);
      bytes = Buffer.alloc(Number(s.size) + 1);
      const { bytesRead } = await fd.read(bytes, 0, bytes.length, 0);
      assert.equal(BigInt(bytesRead), s.size); assert.equal(hash(bytes.subarray(0, bytesRead)), f.sha256, 'deployment file changed');
      const after = await fd.stat({ bigint: true }); assert.equal(after.ctimeNs, s.ctimeNs);
      assert.equal(identity(await lstat(path, { bigint: true })), f.identity);
      return s;
    } finally { bytes?.fill(0); await fd.close(); }
  });
  const state = async (f, i) => {
    await context(); const staged = join(directory, `file-${i}`), target = destination(f.path);
    const a = await inspect(staged, f), b = await inspect(target, f);
    // An extra hardlink, even to our inode, prevents deletion/adoption.
    for (const s of [a, b].filter(Boolean)) assert.equal(s.nlink, BigInt(Number(Boolean(a)) + Number(Boolean(b))));
    if (record.stage === 'installed') assert.ok(!a && b, 'installed file missing or still staged');
    if (record.stage === 'installing') assert.ok(a || b, 'prepared file lost');
    if (record.stage === 'removed') assert.ok(!a && !b, 'removed deployment reappeared');
    if (['detaching', 'detached'].includes(record.stage)) {
      assert.ok(!a, 'detaching file unexpectedly staged');
      if (i < 8) assert.ok(b, 'dependency detach must preserve the remaining client files');
      else if (record.stage === 'detached') assert.ok(!b, 'detached dependency reappeared');
    }
    return { staged, target, a, b };
  };
  // Detect pre-existing drift across the whole set before any next mutation.
  for (const [i, f] of record.files.entries()) await state(f, i);
  if (operation === 'inspect') {
    await context(true); return { stage: record.stage, id: record.id, files: record.files.length, activated: false };
  }
  if (operation === 'remove' && !['removing', 'removed'].includes(record.stage)) await save('removing');
  if (operation === 'detach' && record.stage === 'installed') await save('detaching');
  assert.ok(operation !== 'install' || record.stage === 'installing');
  if (record.stage === 'installing') {
    for (const [i, f] of record.files.entries()) {
      const { staged, target, a, b } = await state(f, i);
      if (!b) { await context(true); await link(staged, target); await checkpoint(`file-${i}:published`); }
      await syncDirectory(dirname(target));
      if (a) { await state(f, i); await context(true); await unlink(staged); await syncDirectory(directory); await checkpoint(`file-${i}:detached`); }
      const view = await state(f, i); assert.ok(!view.a && view.b);
    }
    await save('installed');
  } else if (['detaching', 'removing'].includes(record.stage)) {
    const detaching = record.stage === 'detaching';
    for (const [i, f] of [...record.files.entries()].reverse()) {
      if (detaching && i < 8) break;
      const { staged, target, a, b } = await state(f, i);
      if (b) { await context(true); await unlink(target); await syncDirectory(dirname(target)); await checkpoint(`file-${i}:removed`); }
      if (a) { await state(f, i); await unlink(staged); await syncDirectory(directory); }
    }
    await save(detaching ? 'detached' : 'removed');
  }
  for (const [i, f] of record.files.entries()) await state(f, i);
  await context(true);
  return { stage: record.stage, id: record.id, files: record.files.length, activated: false };
}
