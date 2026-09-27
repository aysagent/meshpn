/** Bounded subprocesses for DNS OS backends. No shell, inherited environment,
 * service installation or implicit authorization to change the host. */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { lstat, stat, realpath, readFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import { ownsBootGuardLock, requireDnsBootGuardLock } from './dns-boot-guard.mjs';

const environment = Object.freeze({ PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL: 'C', LANG: 'C',
  SYSTEMD_PAGER: 'cat', SYSTEMD_PAGERSECURE: '1', SYSTEMD_COLORS: '0' });
const failure = (code) => Object.assign(new Error(code), { code });
export async function assertDnsCommandLock(fd) {
  assert.ok(Number.isSafeInteger(fd) && fd >= 3);
  const s = await stat(`/proc/self/fd/${fd}`);
  assert.ok(s.isFile() && s.uid === process.getuid() && s.nlink === 1 && (s.mode & 0o777) === 0o600);
  assert.ok(ownsBootGuardLock(await readFile(`/proc/self/fdinfo/${fd}`, 'utf8'), process.pid), 'own inherited exclusive flock required');
}

// Internal execution primitive. The fixed-tool factory below pins executable
// identity; other callers (tests) must provide their own trusted executable.
export async function runLockedDnsCommand(file, args, { lockFd, timeoutMs = 10000, maxBytes = 262144, signal } = {}) {
  try {
    assert.ok(typeof file === 'string' && isAbsolute(file) && resolve(file) === file);
    assert.ok(Array.isArray(args) && args.length <= 128 && args.every((s) => typeof s === 'string' && !s.includes('\0') && Buffer.byteLength(s) <= 8192));
    assert.ok(args.reduce((n, s) => n + Buffer.byteLength(s), 0) <= 32768);
    args = [...args];
    assert.ok(Number.isInteger(timeoutMs) && timeoutMs >= 10 && timeoutMs <= 180000);
    assert.ok(Number.isInteger(maxBytes) && maxBytes >= 1 && maxBytes <= 262144);
    assert.ok(!signal?.aborted); await assertDnsCommandLock(lockFd);
  } catch { throw failure('DNS_COMMAND_REFUSED'); }
  if (signal?.aborted) throw failure('DNS_COMMAND_ABORTED');
  return new Promise((resolveResult, reject) => {
    // All helpers inherit the SAME open flock description at fd3. If only the
    // controller dies, its still-running helper retains serialization.
    let proc;
    try { proc = spawn(file, [...args], { env: { ...environment }, detached: true,
      stdio: ['ignore', 'pipe', 'pipe', lockFd] }); }
    catch { return reject(failure('DNS_COMMAND_SPAWN')); }
    let bytes = 0, failed, closed = false; const chunks = [];
    const kill = () => {
      if (!proc.pid) return;
      try { process.kill(-proc.pid, 'SIGKILL'); } catch (e) { if (e.code !== 'ESRCH') failed ??= failure('DNS_COMMAND_CLEANUP'); }
    };
    const abort = (code) => { if (!closed) { failed ??= failure(code); kill(); } };
    const canceled = () => abort('DNS_COMMAND_ABORTED');
    const timer = setTimeout(() => abort('DNS_COMMAND_TIMEOUT'), timeoutMs);
    signal?.addEventListener('abort', canceled, { once: true });
    if (signal?.aborted) canceled();
    proc.once('error', () => { failed ??= failure('DNS_COMMAND_SPAWN'); });
    for (const [stream, keep] of [[proc.stdout, true], [proc.stderr, false]]) stream.on('data', (part) => {
      bytes += part.length;
      if (bytes > maxBytes) abort('DNS_COMMAND_OUTPUT'); else if (keep) chunks.push(part);
    });
    // A tool that accidentally forks must not leave descendants/pipes/lock
    // behind after its leader exits. PID reuse is avoided by acting at exit.
    proc.once('exit', kill);
    proc.once('close', (code, sig) => {
      closed = true; clearTimeout(timer); signal?.removeEventListener('abort', canceled);
      if (failed) return reject(failed);
      if (code !== 0 || sig) return reject(failure('DNS_COMMAND_FAILED'));
      try { resolveResult({ stdout: new TextDecoder('utf8', { fatal: true }).decode(Buffer.concat(chunks)) }); }
      catch { reject(failure('DNS_COMMAND_ENCODING')); }
    });
  });
}

const tools = Object.freeze({ ip: '/usr/bin/ip', busctl: '/usr/bin/busctl', systemctl: '/usr/bin/systemctl', dnsmasq: '/usr/sbin/dnsmasq' });
const instances = new WeakSet();
export function assertDnsSystemCommands(value) { assert.ok(instances.has(value), 'checked DNS system commands required'); }
async function pinnedTool(path) {
  const actual = await realpath(path), entries = [];
  // Validate both the requested spelling and its resolved target (usr-merge
  // symlinks are allowed only when root-owned; directory targets are checked).
  for (const spelling of new Set([path, actual])) {
    let current = spelling;
    for (;;) {
      const s = await lstat(current, { bigint: true });
      assert.equal(s.uid, 0n); assert.ok(s.isSymbolicLink() || !(s.mode & 0o022n));
      if (current !== spelling) {
        const d = await stat(current, { bigint: true }); assert.ok(d.isDirectory() && d.uid === 0n && !(d.mode & 0o022n));
      }
      entries.push(`${current}:${s.dev}:${s.ino}:${s.isDirectory() ? '-' : s.ctimeNs}:${s.mode}`);
      if (current === '/') break; current = dirname(current);
    }
  }
  const s = await stat(actual, { bigint: true }); assert.ok(s.isFile() && (s.mode & 0o111n));
  return { actual, entries };
}
// Read-only identity primitive; does not authorize or execute the supplied path.
export async function inspectDnsSystemExecutable(path) {
  assert.ok(typeof path === 'string' && isAbsolute(path) && resolve(path) === path, 'absolute normalized executable path required');
  return pinnedTool(path);
}
export async function createDnsSystemCommands({ assertAuthority, required = ['ip', 'busctl', 'systemctl'] }) {
  assert.equal(typeof assertAuthority, 'function');
  await assertAuthority(); assert.equal(process.platform, 'linux'); assert.equal(process.getuid(), 0);
  assert.ok(Array.isArray(required) && required.length > 0 && required.length <= 4 && new Set(required).size === required.length);
  assert.ok(required.every((name) => Object.hasOwn(tools, name)));
  required = [...required]; const lockFd = await requireDnsBootGuardLock();
  const pinned = Object.fromEntries(await Promise.all(required.map(async (name) => [name, await pinnedTool(tools[name])])));
  const runner = Object.freeze({
    async run(name, args, options = {}) {
      assert.ok(Object.hasOwn(pinned, name), 'unselected DNS system tool');
      args = [...args]; options = { ...options };
      assert.deepEqual(Object.keys(options).filter((k) => !['timeoutMs', 'maxBytes', 'signal'].includes(k)), []);
      await assertAuthority(); assert.equal(await requireDnsBootGuardLock(), lockFd);
      assert.deepEqual(await pinnedTool(tools[name]), pinned[name], 'DNS executable changed');
      const result = await runLockedDnsCommand(tools[name], args, { ...options, lockFd });
      await assertAuthority(); assert.equal(await requireDnsBootGuardLock(), lockFd);
      assert.deepEqual(await pinnedTool(tools[name]), pinned[name], 'DNS executable changed');
      return result;
    },
  });
  instances.add(runner); return runner;
}
