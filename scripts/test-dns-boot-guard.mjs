import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validateDnsBootPolicy, validateBootNamespace, ownsBootGuardLock, dnsBootGuardUnit, DNS_BOOT_LOCK } from './lib/dns-boot-guard.mjs';
import { runCommand } from './lib/transparent-acceptance.mjs';

const policy = { schema: 1, kind: 'clean-vpn-dns-boot-policy', enabled: true, firewallBackend: 'nf_tables',
  input: { schema: 1, client: 'vps2', id: 'a'.repeat(32) } };
test('boot policy is explicit, bounded to existing guard profiles and an exact firewall backend', () => {
  assert.deepEqual(validateDnsBootPolicy(policy), policy);
  assert.ok(validateDnsBootPolicy({ ...policy, firewallBackend: 'legacy', input: { ...policy.input, client: 'radxa', usbInterface: 'usb0', usbAddress: '192.168.7.1' } }));
});
for (const change of [{ schema: 2 }, { kind: 'other' }, { enabled: false }, { firewallBackend: 'auto' }, { unknown: true }, { input: { ...policy.input, id: '' } }]) {
  test(`reject boot policy ambiguity ${JSON.stringify(change)}`, () => assert.throws(() => validateDnsBootPolicy({ ...policy, ...change })));
}
test('only this process exclusive whole-file flock authorizes a setter', () => {
  const info = 'pos:\t0\nlock:\t1: FLOCK  ADVISORY  WRITE 123 00:1a:456 0 EOF\n';
  assert.equal(ownsBootGuardLock(info, 123), true);
  for (const changed of [info.replace('123', '124'), info.replace('WRITE', 'READ'), info.replace('FLOCK', 'POSIX'), info.replace('0 EOF', '1 EOF'), info.replace('EOF', '16')])
    assert.equal(ownsBootGuardLock(changed, 123), false);
});
test('real flock --no-fork exposes inherited ownership in fdinfo', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'meshpn-boot-lock-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const js = 'const fs=require("node:fs"); let infos=[]; for(const n of fs.readdirSync("/proc/self/fdinfo")){try{infos.push(fs.readFileSync("/proc/self/fdinfo/"+n,"utf8"));}catch(e){if(e.code!=="ENOENT")throw e;}} console.log(JSON.stringify({pid:process.pid,infos}));';
  const result = await runCommand('/usr/bin/flock', ['-n', '-E', '75', '-F', join(directory, 'lock'), process.execPath, '-e', js]);
  assert.equal(result.code, 0, result.stderr); const report = JSON.parse(result.stdout);
  assert.equal(report.infos.filter((info) => ownsBootGuardLock(info, report.pid)).length, 1);
});
test('early unit is pre-network, bounded and cannot release rules on stop', () => {
  const unit = dnsBootGuardUnit('nf_tables');
  for (const line of ['DefaultDependencies=no', 'After=local-fs.target', 'Wants=network-pre.target', 'Before=network-pre.target shutdown.target',
    'RuntimeDirectoryPreserve=yes', 'CapabilityBoundingSet=CAP_NET_ADMIN', 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK', 'Restart=no']) assert.ok(unit.includes(line));
  assert.ok(unit.includes(`/usr/bin/flock -n -E 75 -F ${DNS_BOOT_LOCK}`));
  assert.match(unit, /ExecStartPre=\+\/usr\/bin\/node \/opt\/clean-vpn\/scripts\/dns-boot-guard.mjs --attest-namespace/);
  assert.doesNotMatch(unit, /CAP_SYS_PTRACE/);
  assert.doesNotMatch(unit, /ExecStop|ExecStopPost|\[Install\]|network-online/);
  assert.doesNotMatch(unit, /CAP_NET_RAW/);
  assert.match(dnsBootGuardUnit('legacy'), /CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW/);
  assert.throws(() => dnsBootGuardUnit('auto'));
});
test('namespace attestation has no policy or journal recovery fields', () => {
  const value = { schema: 1, bootId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', netns: 'net:[4026531840]' };
  assert.deepEqual(validateBootNamespace(value), value);
  for (const change of [{ schema: 2 }, { bootId: '' }, { netns: 'mnt:[1]' }, { policy: true }])
    assert.throws(() => validateBootNamespace({ ...value, ...change }));
});
for (const args of [[], ['--start'], ['--inspect'], ['--release'], ['--start', '--config=/tmp/untrusted']]) test(`boot CLI refuses uninstalled/unlocked host invocation ${args}`, async () => {
  const result = await runCommand(process.execPath, ['scripts/dns-boot-guard.mjs', ...args]);
  assert.equal(result.code, 1); assert.equal(result.stdout, ''); assert.match(result.stderr, /^DNS_BOOT_GUARD_REFUSED phase=(arguments|root|pid1|namespace|lock|policy) code=[A-Z0-9_]+\n$/);
});
