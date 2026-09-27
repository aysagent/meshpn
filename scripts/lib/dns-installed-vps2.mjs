/** Read-only installed VPS2 baseline collector. No setter, DNS packet or service start. */
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { lstat, stat, open, readlink } from 'node:fs/promises';
import { dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { assertDnsInstalledAuthority, assertDnsInstalledSession, dnsInstalledAuthorityInfo } from './dns-installed-authority.mjs';
import { createDnsSystemCommands, inspectDnsSystemExecutable } from './dns-system-command.mjs';
import { createDnsSystemBus } from './dns-system-bus.mjs';
import { validateVps2DnsConfig, assessVps2DnsBaseline } from './dns-vps2-baseline.mjs';
import { DNS_NETWORKD_POLICY } from './dns-networkd-policy.mjs';

const unitFields = ['Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'InvocationID', 'NeedDaemonReload'];
export function validateVps2DnsUnit(text, name, busPid) {
  assert.ok(['systemd-resolved', 'systemd-networkd'].includes(name));
  const fields = {};
  for (const line of text.trim().split('\n')) {
    const at = line.indexOf('='); assert.ok(at > 0);
    const key = line.slice(0, at); assert.ok(unitFields.includes(key) && !Object.hasOwn(fields, key)); fields[key] = line.slice(at + 1);
  }
  assert.deepEqual(Object.keys(fields).sort(), [...unitFields].sort());
  assert.equal(fields.Id, `${name}.service`); assert.equal(fields.LoadState, 'loaded');
  assert.equal(fields.ActiveState, 'active'); assert.equal(fields.SubState, 'running');
  assert.equal(fields.NeedDaemonReload, 'no'); assert.match(fields.InvocationID, /^[a-f0-9]{32}$/);
  assert.ok(Number.isInteger(busPid) && busPid > 1); assert.equal(fields.MainPID, String(busPid));
  return fields;
}
const identity = (s) => `${s.dev}:${s.ino}:${s.ctimeNs}:${s.mode}`;
export async function readTrustedDnsText(path, mode, delegated, max = 65536) {
  const owner = (name, uid) => uid === 0n || (delegated && (name === delegated.root || name.startsWith(`${delegated.root}/`)) && uid === BigInt(delegated.uid));
  for (let parent = dirname(path);; parent = dirname(parent)) {
    const p = await lstat(parent, { bigint: true }), target = await stat(parent, { bigint: true });
    assert.ok(owner(parent, p.uid) && (p.isSymbolicLink() || !(p.mode & 0o022n)));
    assert.ok(target.isDirectory() && owner(parent, target.uid) && !(target.mode & 0o022n));
    if (parent === '/') break;
  }
  const fd = await open(path, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
  try {
    const s = await fd.stat({ bigint: true });
    assert.ok(s.isFile() && owner(path, s.uid) && s.nlink === 1n && !(s.mode & 0o022n) && s.size > 0n && s.size <= BigInt(max));
    if (mode !== undefined) assert.equal(s.mode & 0o7777n, BigInt(mode));
    const bytes = Buffer.alloc(Number(s.size) + 1); let used = 0;
    while (used < bytes.length) { const r = await fd.read(bytes, used, bytes.length - used, null); if (!r.bytesRead) break; used += r.bytesRead; }
    assert.equal(BigInt(used), s.size); assert.equal(identity(await fd.stat({ bigint: true })), identity(s));
    assert.equal(identity(await lstat(path, { bigint: true })), identity(s));
    return { text: new TextDecoder('utf8', { fatal: true }).decode(bytes.subarray(0, used)), identity: identity(s) };
  } finally { await fd.close(); }
}
const trustedText = readTrustedDnsText;
export async function inspectInstalledVps2Dns(token) {
  await assertDnsInstalledAuthority(token);
  const info = dnsInstalledAuthorityInfo(token); assert.equal(info.client, 'vps2');
  const config = validateVps2DnsConfig(info.config);
  const commands = await createDnsSystemCommands({ assertAuthority: () => assertDnsInstalledSession(token) });
  const run = (tool, args) => commands.run(tool, args), bus = createDnsSystemBus(run);
  const tracked = new Map();
  const read = async (path, mode, delegated) => {
    const value = await trustedText(path, mode, delegated); tracked.set(path, { value, mode, delegated }); return value.text;
  };
  const units = async () => {
    const result = {};
    for (const [name, service] of [['systemd-resolved', 'org.freedesktop.resolve1'], ['systemd-networkd', 'org.freedesktop.network1']]) {
      const owner = await bus.owner(service), pid = await bus.ownerPid(owner), uid = await bus.ownerUid(owner);
      const unit = validateVps2DnsUnit((await run('systemctl', ['show', `${name}.service`, ...unitFields.map((v) => `--property=${v}`)])).stdout, name, pid);
      const executable = await inspectDnsSystemExecutable(await readlink(`/proc/${pid}/exe`));
      assert.ok([`/usr/lib/systemd/${name}`, `/lib/systemd/${name}`].includes(executable.actual), 'unexpected manager executable');
      assert.equal(await readlink(`/proc/${pid}/ns/net`), info.scope.net);
      result[name] = { owner, pid, uid, unit, executable };
    }
    return result;
  };
  const before = await units(), busId = await bus.id();
  const resolverLink = await lstat('/etc/resolv.conf', { bigint: true });
  assert.ok(resolverLink.isSymbolicLink() && resolverLink.uid === 0n);
  const resolverTarget = await readlink('/etc/resolv.conf');
  assert.equal(resolverTarget, '/run/systemd/resolve/stub-resolv.conf');
  const addresses = JSON.parse((await run('ip', ['-j', 'address', 'show'])).stdout);
  assert.ok(Array.isArray(addresses) && addresses.length <= 64);
  const uplink = addresses.find((v) => v.ifname === config.uplink);
  assert.ok(uplink && Number.isInteger(uplink.ifindex) && uplink.ifindex > 1);
  const evidence = { resolverTarget, addresses,
    resolverText: await read(resolverTarget, 0o644, { root: '/run/systemd/resolve', uid: before['systemd-resolved'].uid }), nssText: await read('/etc/nsswitch.conf'),
    networkState: await read(`/run/systemd/netif/links/${uplink.ifindex}`, undefined, { root: '/run/systemd/netif', uid: before['systemd-networkd'].uid }),
    networkFileSha256: createHash('sha256').update(await read(config.networkFile.path)).digest('hex'),
    networkdExclusion: await read(DNS_NETWORKD_POLICY, 0o644),
    adapterDomainPolicy: JSON.parse(await read('/etc/clean-vpn/dns/domains.json', 0o600)),
    routes4: JSON.parse((await run('ip', ['-j', '-4', 'route', 'show', 'table', 'all'])).stdout),
    manager: await bus.managerSnapshot(before['systemd-resolved'].owner) };
  const result = assessVps2DnsBaseline(config, evidence);
  assert.deepEqual(await units(), before); assert.equal(await bus.id(), busId);
  for (const [path, { value, mode, delegated }] of tracked) assert.deepEqual(await trustedText(path, mode, delegated), value, 'baseline file changed during inspection');
  assert.equal(identity(await lstat('/etc/resolv.conf', { bigint: true })), identity(resolverLink));
  await assertDnsInstalledAuthority(token);
  return result;
}
