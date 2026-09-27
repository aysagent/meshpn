/** Loaded adapter evidence, not a readiness probe or permission to change DNS.
 * Reads credentials privately; neither credential bytes nor hashes are returned. */
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { open, lstat, readlink } from 'node:fs/promises';
import { timingSafeEqual, createHash } from 'node:crypto';
import { assertDnsInstalledAuthority, dnsInstalledAuthorityInfo } from './dns-installed-authority.mjs';
import { createDnsSystemCommands, inspectDnsSystemExecutable } from './dns-system-command.mjs';
import { readTrustedDnsText } from './dns-installed-vps2.mjs';
import { compileDnsAdapterServicePlan } from './dns-adapter-service-plan.mjs';

export const DNS_ADAPTER_UNIT = 'clean-vpn-dns-adapter.service';
const unitPath = `/etc/systemd/system/${DNS_ADAPTER_UNIT}`;
const credentialRoot = `/run/credentials/${DNS_ADAPTER_UNIT}`;
const fields = ['Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'InvocationID', 'NeedDaemonReload',
  'FragmentPath', 'DropInPaths', 'Type', 'DynamicUser', 'ControlGroup'];
const injected = ['NODE_OPTIONS', 'NODE_PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'OPENSSL_CONF',
  'OPENSSL_MODULES', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'NODE_EXTRA_CA_CERTS', 'NODE_USE_SYSTEM_CA'];

export function parseLoadedDnsAdapterUnit(text) {
  assert.ok(typeof text === 'string' && text.length <= 16384);
  const v = {};
  for (const line of text.trim().split('\n')) {
    const i = line.indexOf('='); assert.ok(i > 0);
    const key = line.slice(0, i); assert.ok(fields.includes(key) && !Object.hasOwn(v, key)); v[key] = line.slice(i + 1);
  }
  assert.deepEqual(Object.keys(v).sort(), [...fields].sort());
  for (const [key, value] of Object.entries({ Id: DNS_ADAPTER_UNIT, LoadState: 'loaded', ActiveState: 'active',
    SubState: 'running', NeedDaemonReload: 'no', FragmentPath: unitPath, DropInPaths: '', Type: 'notify', DynamicUser: 'yes' })) assert.equal(v[key], value);
  assert.match(v.MainPID, /^[1-9][0-9]{0,9}$/); assert.ok(Number(v.MainPID) > 1 && Number(v.MainPID) <= 2147483647);
  assert.match(v.InvocationID, /^[a-f0-9]{32}$/);
  assert.equal(v.ControlGroup, `/system.slice/${DNS_ADAPTER_UNIT}`);
  return v;
}

// Reconstruct the exact reviewed unit from the actual process command line and
// disk inputs. The caller separately proves unit/process/file identity.
export function assessLoadedDnsAdapter({ config, unitText, argv, environment, upstream, domainPolicy }) {
  assert.ok(Array.isArray(argv) && argv.length === 12);
  assert.deepEqual(argv.slice(0, 3), ['/usr/bin/node', '--max-old-space-size=192', '/opt/clean-vpn/scripts/dns-exit-adapter.mjs']);
  assert.deepEqual(argv.slice(3, 6), [`--config=${credentialRoot}/upstream.json`, `--domain-policy=${credentialRoot}/domains.json`, `--shared-hmac-key=${credentialRoot}/hmac.key`]);
  const option = (index, name) => { assert.ok(argv[index].startsWith(`--${name}=`)); return argv[index].slice(name.length + 3); };
  const integer = (index, name) => { const raw = option(index, name), n = Number(raw); assert.equal(String(n), raw); return n; };
  const input = { schema: 1, exitIp: option(6, 'exit-ip'), exitPort: integer(7, 'exit-port'),
    publicName: option(8, 'public-name'), listenPort: integer(9, 'listen-port'), readyName: option(10, 'ready-name'), upstream, domainPolicy };
  assert.equal(argv[11], '--systemd-notify');
  assert.equal(input.listenPort, config.adapterPort); assert.equal(input.readyName, config.readyName);
  assert.deepEqual(domainPolicy, config.domainPolicy);
  const plan = compileDnsAdapterServicePlan(input);
  assert.equal(unitText, plan.files.find((f) => f.path === unitPath).contents, 'adapter unit differs from reviewed template');
  assert.ok(Array.isArray(environment) && environment.length <= 256 && environment.every((v) => typeof v === 'string'));
  const env = new Map();
  for (const entry of environment) {
    const at = entry.indexOf('='); assert.ok(at > 0); const key = entry.slice(0, at);
    assert.ok(!env.has(key)); env.set(key, entry.slice(at + 1));
  }
  assert.equal(env.get('CREDENTIALS_DIRECTORY'), credentialRoot);
  for (const key of injected) assert.equal(env.has(key), false, 'injected adapter runtime');
  return { templateMatches: true, configurationMatches: true };
}

async function boundedBytes(path, max, { uid, mode, credentialUid, proc = false } = {}) {
  const fd = await open(path, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
  let bytes, returned = false;
  try {
    const s = await fd.stat({ bigint: true }); assert.ok(s.isFile());
    if (uid !== undefined) assert.equal(s.uid, BigInt(uid));
    if (mode !== undefined) { assert.equal(s.mode & 0o7777n, BigInt(mode)); assert.equal(s.nlink, 1n); }
    if (credentialUid !== undefined) {
      assert.equal(s.nlink, 1n);
      // systemd uses a root-owned ACL-readable file when ACLs are supported,
      // otherwise service ownership on a read-only credential mount.
      assert.ok((s.uid === 0n && [0o400n, 0o440n].includes(s.mode & 0o7777n))
        || (s.uid === BigInt(credentialUid) && (s.mode & 0o7777n) === 0o400n));
    }
    if (!proc) assert.ok(s.size > 0n && s.size <= BigInt(max));
    bytes = Buffer.alloc(max + 1); let used = 0;
    while (used < bytes.length) { const r = await fd.read(bytes, used, bytes.length - used, null); if (!r.bytesRead) break; used += r.bytesRead; }
    assert.ok(used > 0 && used <= max);
    if (!proc) assert.equal(BigInt(used), s.size);
    const identity = (v) => `${v.dev}:${v.ino}:${v.ctimeNs}:${v.mode}:${v.uid}`;
    assert.equal(identity(await fd.stat({ bigint: true })), identity(s));
    assert.equal(identity(await lstat(path, { bigint: true })), identity(s));
    returned = true; return bytes.subarray(0, used);
  } finally { if (!returned) bytes?.fill(0); await fd.close(); }
}
const decode = (bytes) => new TextDecoder('utf8', { fatal: true }).decode(bytes);
const nulList = (bytes) => { const text = decode(bytes); assert.ok(text.endsWith('\0')); return text.slice(0, -1).split('\0'); };

export async function inspectInstalledDnsAdapter(token) {
  await assertDnsInstalledAuthority(token);
  const info = dnsInstalledAuthorityInfo(token);
  const commands = await createDnsSystemCommands({ assertAuthority: () => assertDnsInstalledAuthority(token), required: ['systemctl'] });
  const unit = async () => parseLoadedDnsAdapterUnit((await commands.run('systemctl', ['show', DNS_ADAPTER_UNIT,
    ...fields.map((f) => `--property=${f}`)])).stdout);
  const before = await unit(), pid = Number(before.MainPID), base = `/proc/${pid}`;
  const processState = async () => {
    const status = decode(await boundedBytes(`${base}/status`, 16384, { proc: true }));
    const uid = /^Uid:\s+(\d+)\s+\1\s+\1\s+\1$/m.exec(status); assert.ok(uid); assert.ok(Number(uid[1]) > 0);
    for (const cap of ['CapEff', 'CapPrm', 'CapBnd', 'CapAmb']) assert.match(status, new RegExp(`^${cap}:\\s+0+$`, 'm'));
    assert.match(status, /^NoNewPrivs:\s+1$/m);
    const stat = decode(await boundedBytes(`${base}/stat`, 16384, { proc: true }));
    const end = stat.lastIndexOf(') '); assert.ok(end > 0);
    const startTime = stat.slice(end + 2).split(' ')[19]; assert.match(startTime, /^\d+$/);
    const executable = await inspectDnsSystemExecutable(await readlink(`${base}/exe`));
    assert.equal(executable.actual, (await inspectDnsSystemExecutable('/usr/bin/node')).actual);
    const netns = await readlink(`${base}/ns/net`); assert.equal(netns, info.scope.net);
    const cgroup = decode(await boundedBytes(`${base}/cgroup`, 16384, { proc: true }));
    assert.ok(cgroup.split('\n').some((v) => v === `0::${before.ControlGroup}`
      || /^\d+:name=systemd:/.test(v) && v.slice(v.lastIndexOf(':') + 1) === before.ControlGroup), 'adapter cgroup mismatch');
    const mounts = decode(await boundedBytes(`${base}/mountinfo`, 262144, { proc: true }));
    const credentialMount = mounts.split('\n').filter((v) => v.split(' ')[4] === credentialRoot);
    assert.equal(credentialMount.length, 1); assert.ok(credentialMount[0].split(' ')[5].split(',').includes('ro'));
    return { uid: Number(uid[1]), startTime, executable, netns, cgroup, credentialMount };
  };
  const processBefore = await processState();
  const argv = nulList(await boundedBytes(`${base}/cmdline`, 16384, { proc: true }));
  const environment = nulList(await boundedBytes(`${base}/environ`, 65536, { proc: true }));
  const unitBefore = await readTrustedDnsText(unitPath, 0o644);
  const selected = {}, sources = [];
  // Parent path ownership is checked via the installed authority. Loaded
  // credentials are accessed in the pinned process mount namespace, not ours.
  for (const [name, max] of [['upstream.json', 131072], ['domains.json', 16384], ['hmac.key', 32]]) {
    const source = `/etc/clean-vpn/dns/${name}`;
    const loaded = `${base}/root${credentialRoot}/${name}`;
    const expected = await boundedBytes(source, max, { uid: 0, mode: 0o600 });
    let actual;
    try {
      actual = await boundedBytes(loaded, max, { credentialUid: processBefore.uid });
      assert.equal(actual.length, expected.length); assert.ok(timingSafeEqual(actual, expected), 'loaded credential differs');
      if (name === 'hmac.key') assert.equal(expected.length, 32);
      else selected[name] = JSON.parse(decode(expected));
      sources.push({ source, max, digest: createHash('sha256').update(expected).digest('hex') });
      const again = await boundedBytes(source, max, { uid: 0, mode: 0o600 });
      try { assert.ok(expected.length === again.length && timingSafeEqual(expected, again), 'credential source changed'); }
      finally { again.fill(0); }
    } finally { expected.fill(0); actual?.fill(0); }
  }
  assessLoadedDnsAdapter({ config: info.config, unitText: unitBefore.text, argv, environment,
    upstream: selected['upstream.json'], domainPolicy: selected['domains.json'] });
  assert.deepEqual(await processState(), processBefore); assert.deepEqual(await unit(), before);
  assert.deepEqual(nulList(await boundedBytes(`${base}/cmdline`, 16384, { proc: true })), argv);
  assert.deepEqual(nulList(await boundedBytes(`${base}/environ`, 65536, { proc: true })), environment);
  for (const { source, max, digest } of sources) {
    const current = await boundedBytes(source, max, { uid: 0, mode: 0o600 });
    try { assert.equal(createHash('sha256').update(current).digest('hex') === digest, true, 'credential source changed during inspection'); }
    finally { current.fill(0); }
  }
  assert.deepEqual(await readTrustedDnsText(unitPath, 0o644), unitBefore);
  await assertDnsInstalledAuthority(token);
  return { schema: 1, kind: 'clean-vpn-dns-loaded-adapter', mode: 'read-only', loadedCredentialsVerified: true,
    activationAuthorized: false, systemSettingsChanged: false, dnsQueriesSent: 0,
    limitations: ['point-in-time-not-service-lock', 'no-listener-ownership-or-readiness-proof', 'not-a-leak-test'] };
}
