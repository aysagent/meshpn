/** Read-only gate for a future installed client entrypoint. Boot guard opt-in
 * alone is NOT permission to switch DNS. No service calls, writes or DNS here. */
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { open, opendir, lstat, realpath, readFile, readlink } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { requireDnsBootGuardLock, validateDnsBootPolicy, DNS_BOOT_POLICY } from './dns-boot-guard.mjs';
import { inspectDnsSystemExecutable } from './dns-system-command.mjs';

const ROOT = '/opt/clean-vpn';
const SELF = 'scripts/lib/dns-installed-authority.mjs';
const ENTRY = 'scripts/dns-client.mjs';
const OPT_IN = '/etc/clean-vpn/dns/client-opt-in.json';
const CONFIG = '/etc/clean-vpn/dns/client.json';
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const keys = (v, names) => {
  assert.ok(v && typeof v === 'object' && !Array.isArray(v));
  assert.deepEqual(Object.keys(v).sort(), [...names].sort());
};
const identity = (s) => `${s.dev}:${s.ino}:${s.ctimeNs}:${s.mode}`;
export function validateDnsClientOptIn(v) {
  keys(v, ['schema', 'kind', 'enabled', 'client', 'guardId', 'bundleSha256', 'configSha256']);
  assert.equal(v.schema, 1); assert.equal(v.kind, 'clean-vpn-dns-client-opt-in'); assert.equal(v.enabled, true);
  assert.ok(['vps2', 'radxa'].includes(v.client)); assert.match(v.guardId, /^[a-f0-9]{32}$/);
  for (const name of ['bundleSha256', 'configSha256']) assert.match(v[name], /^[a-f0-9]{64}$/);
  return v;
}
export function validateDnsInstalledBundle(v) {
  keys(v, ['schema', 'kind', 'files']);
  assert.equal(v.schema, 1); assert.equal(v.kind, 'clean-vpn-dns-code-bundle');
  assert.ok(v.files && typeof v.files === 'object' && !Array.isArray(v.files));
  assert.ok(Object.keys(v.files).length > 0 && Object.keys(v.files).length <= 512);
  for (const [path, digest] of Object.entries(v.files)) {
    assert.match(path, /^scripts\/(?:[a-zA-Z0-9_-]+\/)*[a-zA-Z0-9_-]+\.(?:mjs|js|json)$/);
    assert.match(digest, /^[a-f0-9]{64}$/);
  }
  for (const required of [SELF, ENTRY]) assert.ok(Object.hasOwn(v.files, required), 'client entrypoint and authority module must be in bundle');
  return v;
}
async function directory(path, uid, publicCode = false) {
  const s = await lstat(path, { bigint: true });
  assert.ok(s.isDirectory() && s.uid === BigInt(uid) && !(s.mode & 0o022n), 'untrusted installed directory');
  if (publicCode) assert.equal(s.mode & 0o7777n, 0o755n, 'public code directory required');
  return `${s.dev}:${s.ino}:${s.mode}`; // Ordinary directory entry changes do not repin it.
}
async function boundedFile(path, uid, mode, max) {
  const fd = await open(path, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
  try {
    const before = await fd.stat({ bigint: true });
    assert.ok(before.isFile() && before.uid === BigInt(uid) && before.nlink === 1n && (before.mode & 0o7777n) === BigInt(mode));
    assert.ok(before.size > 0n && before.size <= BigInt(max));
    const bytes = Buffer.alloc(Number(before.size) + 1); let size = 0;
    while (size < bytes.length) {
      const r = await fd.read(bytes, size, bytes.length - size, null); if (!r.bytesRead) break; size += r.bytesRead;
    }
    assert.equal(BigInt(size), before.size); assert.equal(identity(await fd.stat({ bigint: true })), identity(before));
    assert.equal(identity(await lstat(path, { bigint: true })), identity(before));
    return { bytes: bytes.subarray(0, size), identity: identity(before) };
  } finally { await fd.close(); }
}
const decode = (bytes) => JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes));

/** Read-only inventory primitive, also used on private roots in tests.
 * Its result is data, NEVER an installed-authority token. */
export async function inspectDnsInstalledBundle(root, uid) {
  assert.equal(await realpath(root), root); assert.ok(Number.isSafeInteger(uid) && uid >= 0);
  const rootIdentity = await directory(root, uid, true), manifest = await boundedFile(join(root, 'bundle.json'), uid, 0o644, 131072);
  const bundle = validateDnsInstalledBundle(decode(manifest.bytes)), files = {}, directories = {};
  let entries = 0, totalBytes = 0;
  async function walk(relative) {
    const path = join(root, relative); directories[relative] = await directory(path, uid, true);
    for await (const entry of await opendir(path)) {
      assert.ok(++entries <= 1024, 'bundle inventory limit');
      const name = relative ? `${relative}/${entry.name}` : entry.name;
      if (name === 'bundle.json') continue;
      if (entry.isDirectory()) { await walk(name); continue; }
      assert.ok(entry.isFile() && Object.hasOwn(bundle.files, name), 'unlisted or non-regular bundle file');
      const value = await boundedFile(join(root, name), uid, 0o644, 1048576);
      totalBytes += value.bytes.length; assert.ok(totalBytes <= 16 * 1024 * 1024, 'bundle total size limit');
      assert.equal(hash(value.bytes), bundle.files[name], 'bundle content changed'); files[name] = value.identity;
    }
  }
  await walk(''); assert.deepEqual(Object.keys(files).sort(), Object.keys(bundle.files).sort(), 'bundle file missing');
  assert.equal(await directory(root, uid), rootIdentity);
  assert.equal((await boundedFile(join(root, 'bundle.json'), uid, 0o644, 131072)).identity, manifest.identity);
  return { rootIdentity, manifestIdentity: manifest.identity, sha256: hash(manifest.bytes), files, directories };
}

const instances = new WeakMap();
async function runtimeScope() {
  assert.equal(process.platform, 'linux'); assert.equal(process.getuid(), 0);
  assert.equal(fileURLToPath(import.meta.url), `${ROOT}/${SELF}`, 'installed entrypoint required');
  assert.equal(process.argv[1], `${ROOT}/${ENTRY}`, 'fixed client entrypoint required');
  const [major, minor] = process.versions.node.split('.').map(Number);
  assert.ok(major === 24 && minor >= 13, 'supported Node 24.13+ runtime required');
  assert.equal((await readFile('/proc/1/comm', 'utf8')).trim(), 'systemd');
  assert.ok(process.execArgv.every((v) => v === '--max-old-space-size=192'), 'unsupported Node arguments');
  for (const key of ['NODE_OPTIONS', 'NODE_PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'OPENSSL_CONF', 'OPENSSL_MODULES',
    'SSL_CERT_FILE', 'SSL_CERT_DIR', 'NODE_EXTRA_CA_CERTS', 'NODE_USE_SYSTEM_CA'])
    assert.equal(process.env[key], undefined, 'injected runtime environment');
  const scope = {};
  for (const key of ['net', 'mnt', 'pid']) {
    scope[key] = await readlink(`/proc/self/ns/${key}`);
    assert.equal(scope[key], await readlink(`/proc/1/ns/${key}`), 'initial namespace required');
  }
  return { scope, bootId: (await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim(), lockFd: await requireDnsBootGuardLock() };
}
async function configuration() {
  const directories = {};
  for (const path of ['/', '/opt', ROOT, '/etc', '/etc/clean-vpn', '/etc/clean-vpn/dns'])
    directories[path] = await directory(path, 0, ['/', '/opt', ROOT].includes(path));
  const opt = await boundedFile(OPT_IN, 0, 0o600, 2048), permit = validateDnsClientOptIn(decode(opt.bytes));
  const config = await boundedFile(CONFIG, 0, 0o600, 65536), guard = await boundedFile(DNS_BOOT_POLICY, 0, 0o600, 8192);
  const policy = validateDnsBootPolicy(decode(guard.bytes)), value = decode(config.bytes);
  assert.equal(permit.guardId, policy.input.id); assert.equal(permit.client, policy.input.client);
  assert.equal(hash(config.bytes), permit.configSha256);
  assert.equal(value.schema, 1); assert.equal(value.client, permit.client);
  // Client-specific ownership/config semantics must still be checked by the OS
  // factory. A hash proves the selected input, not suitability for takeover.
  return { directories, permit, config: value, optIdentity: opt.identity, configIdentity: config.identity, guardIdentity: guard.identity };
}
export async function loadDnsInstalledAuthority() {
  const scope = await runtimeScope(), input = await configuration();
  const bundle = await inspectDnsInstalledBundle(ROOT, 0);
  assert.equal(bundle.sha256, input.permit.bundleSha256, 'unapproved code bundle');
  // Pin requested spelling (including root-owned symlinks) AND canonical target.
  const executable = await inspectDnsSystemExecutable('/usr/bin/node');
  assert.equal(await realpath(process.execPath), executable.actual, 'fixed system interpreter required');
  const token = Object.freeze({}); instances.set(token, { scope, input, bundle, executable });
  await assertDnsInstalledAuthority(token); return token;
}
export function dnsInstalledAuthorityInfo(token) {
  const v = instances.get(token); assert.ok(v, 'installed authority token required');
  return structuredClone({ client: v.input.permit.client, guardId: v.input.permit.guardId, config: v.input.config, ...v.scope });
}
export async function assertDnsInstalledAuthority(token) {
  const v = instances.get(token); assert.ok(v, 'installed authority token required');
  assert.deepEqual(await runtimeScope(), v.scope); assert.deepEqual(await configuration(), v.input);
  assert.equal(await realpath(process.execPath), v.executable.actual);
  assert.deepEqual(await inspectDnsSystemExecutable('/usr/bin/node'), v.executable);
  assert.equal((await boundedFile(`${ROOT}/bundle.json`, 0, 0o644, 131072)).identity, v.bundle.manifestIdentity);
  for (const [path, expected] of Object.entries(v.bundle.directories)) assert.equal(await directory(join(ROOT, path), 0, true), expected);
  for (const [path, expected] of Object.entries(v.bundle.files)) assert.equal(identity(await lstat(join(ROOT, path), { bigint: true })), expected);
  // Each process hashes the complete bundle once, then pins file metadata.
  // This is not a sandbox or atomic CAS against concurrent hostile root.
}
