/** Fixed-layout early guard. No DNS journal reads, baseline setters or release CLI. */
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { open, lstat, stat, readFile, readlink, readdir, realpath, rename } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { compileDnsClientGuard, createDnsClientGuard } from './dns-client-guard.mjs';
import { createDnsGuardJournalBackend } from './dns-client-guard-journal.mjs';

export const DNS_BOOT_POLICY = '/etc/clean-vpn/dns/guard-policy.json';
export const DNS_BOOT_LOCK = '/run/clean-vpn-dns-guard/lock';
const NAMESPACE_ANCHOR = '/run/clean-vpn-dns-guard/namespace.json';
export function validateBootNamespace(value) {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), ['schema', 'bootId', 'netns'].sort());
  assert.equal(value.schema, 1); assert.match(value.bootId, /^[a-f0-9-]{36}$/);
  assert.match(value.netns, /^net:\[\d+\]$/); return value;
}
const namespaceIdentity = async () => validateBootNamespace({ schema: 1,
  bootId: (await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim(), netns: await readlink('/proc/self/ns/net') });
// Tiny privileged ExecStartPre, before the firewall process drops capabilities.
// This is only an ephemeral attestation, never a DNS recovery journal.
export async function attestDnsBootNamespace({ onPhase = () => {} } = {}) {
  onPhase('attestation-root');
  assert.equal(process.platform, 'linux'); assert.equal(process.getuid(), 0);
  onPhase('attestation-pid1');
  assert.equal((await readFile('/proc/1/comm', 'utf8')).trim(), 'systemd');
  onPhase('attestation-run'); await trustedDirectory('/run');
  onPhase('attestation-directory'); await trustedDirectory('/run/clean-vpn-dns-guard', true);
  onPhase('attestation-namespace');
  const value = await namespaceIdentity(); assert.equal(value.netns, await readlink('/proc/1/ns/net'));
  onPhase('attestation-write');
  const temporary = `${NAMESPACE_ANCHOR}.${randomBytes(12).toString('hex')}.tmp`;
  const fd = await open(temporary, 'wx', 0o600);
  try { await fd.writeFile(`${JSON.stringify(value)}\n`); await fd.sync(); } finally { await fd.close(); }
  await rename(temporary, NAMESPACE_ANCHOR);
  const dir = await open('/run/clean-vpn-dns-guard', constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await dir.sync(); } finally { await dir.close(); }
}
async function readNamespaceAnchor() {
  await trustedDirectory('/run'); await trustedDirectory('/run/clean-vpn-dns-guard', true);
  const fd = await open(NAMESPACE_ANCHOR, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const s = await fd.stat({ bigint: true });
    assert.ok(s.isFile() && s.uid === 0n && s.nlink === 1n && (s.mode & 0o777n) === 0o600n && s.size > 0n && s.size <= 512n);
    const bytes = Buffer.alloc(513), { bytesRead } = await fd.read(bytes, 0, bytes.length, 0);
    assert.equal(BigInt(bytesRead), s.size); assert.equal((await fd.stat({ bigint: true })).ctimeNs, s.ctimeNs);
    return validateBootNamespace(JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes.subarray(0, bytesRead))));
  } finally { await fd.close(); }
}
// Read-only evidence for post-disable inspection; does not grant authority.
export { readNamespaceAnchor as readDnsBootNamespaceAnchor };
export function validateDnsBootPolicy(value) {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), ['schema', 'kind', 'enabled', 'firewallBackend', 'input'].sort());
  assert.equal(value.schema, 1); assert.equal(value.kind, 'clean-vpn-dns-boot-policy'); assert.equal(value.enabled, true);
  assert.ok(['legacy', 'nf_tables'].includes(value.firewallBackend)); compileDnsClientGuard(value.input);
  return value;
}
export function ownsBootGuardLock(info, pid) {
  assert.ok(Number.isSafeInteger(pid) && pid > 0);
  return info.split('\n').some((line) => new RegExp(`^lock:\\s+\\d+: FLOCK\\s+ADVISORY\\s+WRITE\\s+${pid}\\s+[0-9a-f]+:[0-9a-f]+:\\d+\\s+0 EOF$`).test(line));
}
async function trustedDirectory(path, privateMode = false) {
  const s = await lstat(path);
  assert.ok(s.isDirectory() && !s.isSymbolicLink() && s.uid === 0 && !(s.mode & 0o022));
  if (privateMode) assert.equal(s.mode & 0o777, 0o700);
}
async function lockHeld() {
  await trustedDirectory('/run'); await trustedDirectory('/run/clean-vpn-dns-guard', true);
  const s = await lstat(DNS_BOOT_LOCK);
  assert.ok(s.isFile() && !s.isSymbolicLink() && s.uid === 0 && s.nlink === 1 && (s.mode & 0o777) === 0o600);
  const fds = await readdir('/proc/self/fdinfo'); assert.ok(fds.length <= 128);
  for (const name of fds.filter((n) => /^\d+$/.test(n))) {
    try {
      const fd = await stat(`/proc/self/fd/${name}`);
      if (fd.dev === s.dev && fd.ino === s.ino && ownsBootGuardLock(await readFile(`/proc/self/fdinfo/${name}`, 'utf8'), process.pid)) return Number(name);
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  throw new Error('inherited exclusive guard flock required');
}
// Shared by fixed-layout client OS helpers; this does not acquire a new lock.
export const requireDnsBootGuardLock = lockHeld;
async function readPolicy() {
  for (const path of ['/etc', '/etc/clean-vpn', '/etc/clean-vpn/dns']) await trustedDirectory(path);
  const fd = await open(DNS_BOOT_POLICY, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
  try {
    const s = await fd.stat({ bigint: true });
    assert.ok(s.isFile() && s.uid === 0n && s.nlink === 1n && (s.mode & 0o777n) === 0o600n && s.size > 0n && s.size <= 8192n);
    const bytes = Buffer.alloc(8193), { bytesRead } = await fd.read(bytes, 0, bytes.length, 0);
    assert.equal(BigInt(bytesRead), s.size); assert.equal((await fd.stat({ bigint: true })).ctimeNs, s.ctimeNs);
    return { policy: validateDnsBootPolicy(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, bytesRead)))),
      identity: `${s.dev}:${s.ino}:${s.ctimeNs}` };
  } finally { await fd.close(); }
}
export async function loadDnsBootGuard({ onPhase = () => {} } = {}) {
  onPhase('root');
  assert.equal(process.platform, 'linux'); assert.equal(process.getuid(), 0);
  onPhase('pid1');
  assert.equal((await readFile('/proc/1/comm', 'utf8')).trim(), 'systemd');
  onPhase('namespace');
  const netns = await readlink('/proc/self/ns/net');
  try { assert.equal(netns, await readlink('/proc/1/ns/net')); }
  catch (error) {
    if (error.code !== 'EACCES') throw error;
    // The restricted firewall process cannot ptrace PID1's namespace symlink.
    // A separate, fixed pre-start attests it; stale boots/namespaces are refused.
    assert.deepEqual(await namespaceIdentity(), await readNamespaceAnchor(), 'initial network namespace required');
  }
  onPhase('lock'); const lockFd = await lockHeld(); onPhase('policy'); const configured = await readPolicy();
  const bootId = (await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim();
  const execute = promisify(execFile);
  const env = { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL: 'C' };
  const binary = (family, suffix = '') => `/usr/sbin/${family === 4 ? 'iptables' : 'ip6tables'}${suffix}`;
  const toolIdentity = async () => {
    const identities = [];
    for (const family of [4, 6]) for (const suffix of ['', '-restore']) {
      const path = await realpath(binary(family, suffix)), s = await stat(path, { bigint: true });
      assert.ok(s.isFile() && s.uid === 0n && !(s.mode & 0o022n));
      identities.push(`${path}:${s.dev}:${s.ino}:${s.ctimeNs}`);
    }
    return identities;
  };
  onPhase('tool-identity'); const toolsBefore = await toolIdentity();
  const run = async (family, suffix, args, input) => {
    // A mutating child inherits the open flock description. Parent SIGKILL must
    // not release serialization while iptables-restore is still committing.
    if (input === undefined) return (await execute(binary(family, suffix), args, { env, timeout: 5000, killSignal: 'SIGKILL', maxBuffer: 262144 })).stdout;
    return new Promise((resolve, reject) => {
      const proc = spawn(binary(family, suffix), args, { env, stdio: ['pipe', 'pipe', 'pipe', lockFd] });
      let output = '', bytes = 0, failure;
      const abort = (code) => { failure ??= Object.assign(new Error(code), { code }); proc.kill('SIGKILL'); };
      const timer = setTimeout(() => abort('DNS_GUARD_RESTORE_TIMEOUT'), 5000);
      proc.on('error', (error) => { failure ??= error; });
      for (const [stream, keep] of [[proc.stdout, true], [proc.stderr, false]]) stream.on('data', (part) => {
        bytes += part.length; if (bytes > 262144) abort('DNS_GUARD_RESTORE_OUTPUT'); else if (keep) output += part;
      });
      proc.once('close', (code) => { clearTimeout(timer); if (failure || code !== 0) reject(failure ?? Object.assign(new Error('DNS_GUARD_RESTORE_FAILED'), { code: 'DNS_GUARD_RESTORE_FAILED' })); else resolve(output); });
      proc.stdin.on('error', () => {}); proc.stdin.end(input);
    });
  };
  const versions = [];
  onPhase('tool-version');
  for (const family of [4, 6]) for (const suffix of ['', '-restore']) {
    const version = (await run(family, suffix, ['--version'])).trim();
    assert.equal(/\((nf_tables|legacy)\)/.exec(version)?.[1], configured.policy.firewallBackend, 'firewall backend changed'); versions.push(version);
  }
  const assertContext = async () => {
    await lockHeld(); assert.equal(await readlink('/proc/self/ns/net'), netns);
    assert.equal((await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim(), bootId);
    assert.deepEqual(await readPolicy(), configured, 'boot policy changed during operation');
    assert.deepEqual(await toolIdentity(), toolsBefore, 'firewall tools changed during operation');
  };
  const guard = createDnsClientGuard({ input: configured.policy.input, assertContext,
    read: (family) => run(family, '', ['-w', '2', '-S']),
    restore: (family, batch) => run(family, '-restore', ['--wait', '2', '--noflush'], batch) });
  return { guard, policy: configured.policy, versions,
    createJournalBackend({ context, authorizeRelease }) {
      const { id, ...config } = configured.policy.input;
      return createDnsGuardJournalBackend({ config, authorizeRelease,
        installedInput: async () => { await assertContext(); return structuredClone(configured.policy.input); },
        context: async () => {
          await assertContext(); const value = await context();
          assert.equal(value.bootId, bootId); assert.equal(value.netns, netns);
          assert.deepEqual(value.firewall, { ipv4: configured.policy.firewallBackend, ipv6: configured.policy.firewallBackend });
          return value;
        },
        read: (family) => run(family, '', ['-w', '2', '-S']),
        restore: (family, batch) => run(family, '-restore', ['--wait', '2', '--noflush'], batch) });
    } };
}

export function dnsBootGuardUnit(backend) {
  assert.ok(['legacy', 'nf_tables'].includes(backend));
  return `[Unit]
Description=clean-vpn early DNS guard (stop retains rules)
DefaultDependencies=no
After=local-fs.target
Wants=network-pre.target
Before=network-pre.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=root
UMask=0077
RuntimeDirectory=clean-vpn-dns-guard
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
ExecStartPre=+/usr/bin/node /opt/clean-vpn/scripts/dns-boot-guard.mjs --attest-namespace
ExecStart=/usr/bin/flock -n -E 75 -F ${DNS_BOOT_LOCK} /usr/bin/node /opt/clean-vpn/scripts/dns-boot-guard.mjs --start
Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
UnsetEnvironment=NODE_OPTIONS NODE_PATH LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT OPENSSL_CONF OPENSSL_MODULES
Restart=no
TimeoutStartSec=45
TimeoutStopSec=10
KillMode=control-group
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN${backend === 'legacy' ? ' CAP_NET_RAW' : ''}
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=/run
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LimitCORE=0
LimitNOFILE=128
TasksMax=32
StandardInput=null
StandardOutput=journal
StandardError=journal
`;
}
