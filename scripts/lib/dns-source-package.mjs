/** Offline source packaging, shared by the operator command and VM builder.
 * No installation, credentials, network, subprocesses or changes outside output.
 * A content hash identifies the snapshot; it is not a signature or opt-in. */
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { open, readdir, lstat, realpath, mkdir, chmod } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { inspectDnsInstalledBundle, validateDnsInstalledBundle } from './dns-installed-authority.mjs';

const hash = (v) => createHash('sha256').update(v).digest('hex');
const identity = (s) => `${s.dev}:${s.ino}:${s.mode}:${s.size}:${s.ctimeNs}`;
async function snapshot(source) {
  const files = new Map(); let entries = 0, bytes = 0;
  async function walk(relative) {
    const path = join(source, relative), before = await lstat(path, { bigint: true });
    assert.ok(before.isDirectory(), 'source directory must not be a symlink');
    const names = (await readdir(path)).sort();
    for (const name of names) {
      assert.ok(++entries <= 4096, 'source inventory limit');
      const child = `${relative}/${name}`, full = join(source, child), s = await lstat(full, { bigint: true });
      assert.ok(!s.isSymbolicLink(), 'source symlinks are unsupported');
      if (s.isDirectory()) { await walk(child); continue; }
      if (!/\.(?:js|mjs)$/.test(name)) continue;
      assert.match(child, /^scripts\/(?:[a-zA-Z0-9_-]+\/)*[a-zA-Z0-9_-]+\.(?:mjs|js)$/);
      assert.ok(s.isFile() && s.nlink === 1n && s.size > 0n && s.size <= 1048576n, 'invalid code file');
      assert.ok(files.size < 512 && bytes + Number(s.size) <= 16 * 1024 * 1024, 'source size limit');
      const fd = await open(full, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      let contents;
      try {
        assert.equal(identity(await fd.stat({ bigint: true })), identity(s));
        contents = Buffer.alloc(Number(s.size) + 1); let length = 0;
        while (length < contents.length) {
          const r = await fd.read(contents, length, contents.length - length, null);
          if (!r.bytesRead) break; length += r.bytesRead;
        }
        assert.equal(length, Number(s.size), 'source size changed');
        assert.equal(identity(await fd.stat({ bigint: true })), identity(s));
        assert.equal(identity(await lstat(full, { bigint: true })), identity(s));
        contents = contents.subarray(0, length);
      } finally { await fd.close(); }
      bytes += contents.length; files.set(child, { contents, sha256: hash(contents), identity: identity(s) });
    }
    assert.equal(identity(await lstat(path, { bigint: true })), identity(before), 'source directory changed');
  }
  await walk('scripts');
  validateDnsInstalledBundle({ schema: 1, kind: 'clean-vpn-dns-code-bundle',
    files: Object.fromEntries([...files].map(([name, value]) => [name, value.sha256])) });
  return { files, bytes };
}
export async function packageDnsSource({ source, output }) {
  assert.equal(typeof source, 'string'); assert.equal(typeof output, 'string');
  assert.equal(resolve(source), source); assert.equal(resolve(output), output);
  assert.equal(await realpath(source), source);
  assert.ok(output !== source && !output.startsWith(`${source}/`), 'output must be outside source');
  const parent = dirname(output); assert.equal(await realpath(parent), parent);
  const before = await snapshot(source);
  const parentIdentity = identity(await lstat(parent, { bigint: true }));
  // mkdir, not recursive mkdir: an existing destination is never reused.
  await mkdir(output, { mode: 0o755 }); await chmod(output, 0o755);
  const root = await lstat(output, { bigint: true });
  const directories = new Set([output]);
  const write = async (path, contents) => {
    const fd = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o644);
    try { await fd.chmod(0o644); await fd.writeFile(contents); await fd.sync(); } finally { await fd.close(); }
  };
  for (const [name, value] of before.files) {
    let path = output;
    for (const part of name.split('/').slice(0, -1)) {
      path = join(path, part);
      if (!directories.has(path)) { await mkdir(path, { mode: 0o755 }); await chmod(path, 0o755); directories.add(path); }
    }
    await write(join(output, name), value.contents);
  }
  const after = await snapshot(source);
  const descriptors = (s) => [...s.files].map(([name, v]) => [name, v.sha256, v.identity]);
  assert.deepEqual(descriptors(after), descriptors(before), 'source changed during packaging');
  assert.equal(await realpath(output), output);
  const current = await lstat(output, { bigint: true });
  assert.equal(current.dev, root.dev); assert.equal(current.ino, root.ino);
  // Parent entry timestamps necessarily change when output is created.
  const p = await lstat(parent, { bigint: true });
  assert.equal(`${p.dev}:${p.ino}:${p.mode}`, parentIdentity.split(':').slice(0, 3).join(':'));
  const manifest = `${JSON.stringify({ schema: 1, kind: 'clean-vpn-dns-code-bundle',
    files: Object.fromEntries([...before.files].map(([name, v]) => [name, v.sha256])) }, null, 2)}\n`;
  // Manifest is the last file, so interrupted copies do not look complete.
  await write(join(output, 'bundle.json'), manifest);
  const inventory = await inspectDnsInstalledBundle(output, process.getuid());
  assert.equal(inventory.sha256, hash(manifest));
  for (const path of [...directories].reverse()) {
    const fd = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { await fd.sync(); } finally { await fd.close(); }
  }
  return { schema: 1, kind: 'clean-vpn-dns-source-package', output, files: before.files.size,
    codeBytes: before.bytes, bundleSha256: inventory.sha256, systemSettingsChanged: false,
    dnsQueriesSent: 0, installationPerformed: false };
}
