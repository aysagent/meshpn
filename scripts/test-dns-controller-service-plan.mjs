import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { compileDnsControllerServicePlan } from './lib/dns-controller-service-plan.mjs';
const input = { schema: 1, client: 'vps2', firewallBackend: 'legacy' };
test('controller units are fixed offline artifacts without install or boot-enable authority', () => {
  const p = compileDnsControllerServicePlan(input);
  assert.equal(p.installationAllowed, false); assert.equal(p.systemSettingsChanged, false); assert.equal(p.dnsQueriesSent, 0);
  assert.ok(p.limitations.includes('service-plan-is-not-loaded-service-proof'));
  assert.equal(p.files.length, 4); assert.deepEqual(p, compileDnsControllerServicePlan(input));
  for (const f of p.files) {
    assert.equal(f.mode, '0644'); assert.equal(f.sha256, createHash('sha256').update(f.contents).digest('hex'));
    assert.ok(!f.contents.includes('[Install]')); assert.ok(!f.contents.includes('ExecStop='));
  }
});
test('start uses the shared flock/dependencies; explicit disable works without adapter', () => {
  const [start, disable, resolved, networkd] = compileDnsControllerServicePlan(input).files;
  assert.match(start.contents, /BindsTo=clean-vpn-dns-guard.service clean-vpn-dns-adapter.service systemd-resolved.service systemd-networkd.service/);
  assert.match(start.contents, /ExecStart=\/usr\/bin\/flock -n -E 75 -F \/run\/clean-vpn-dns-guard\/lock \/usr\/bin\/node --max-old-space-size=192 \/opt\/clean-vpn\/scripts\/dns-client.mjs --start\n/);
  assert.match(start.contents, /RemainAfterExit=yes/); assert.match(start.contents, /KillMode=control-group/);
  assert.match(disable.contents, /--disable\n/); assert.ok(!disable.contents.includes('clean-vpn-dns-adapter.service'));
  assert.match(disable.contents, /After=clean-vpn-dns-client.service /); assert.match(disable.contents, /Conflicts=clean-vpn-dns-client.service/);
  for (const f of [resolved, networkd]) assert.equal(f.contents, '[Unit]\nRequires=clean-vpn-dns-guard.service\nAfter=clean-vpn-dns-guard.service\n');
});
test('controller retains initial namespaces and bounded privileges for proc evidence and firewall', () => {
  for (const f of compileDnsControllerServicePlan(input).files.slice(0, 2)) {
    for (const key of ['ProtectSystem', 'ProtectHome', 'PrivateTmp', 'PrivateDevices', 'PrivateNetwork', 'PrivateUsers', 'ProtectProc', 'ReadWritePaths']) assert.ok(!f.contents.includes(`${key}=`));
    for (const line of ['User=root', 'NoNewPrivileges=yes', 'RestrictNamespaces=yes', 'LimitCORE=0', 'Restart=no', 'TimeoutStartSec=180']) assert.ok(f.contents.split('\n').includes(line));
    assert.match(f.contents, /CAP_SYS_PTRACE CAP_NET_RAW\n/);
  }
  assert.ok(!compileDnsControllerServicePlan({ ...input, firewallBackend: 'nf_tables' }).files[0].contents.includes('CAP_NET_RAW'));
});
test('renderer refuses unimplemented clients, arbitrary paths/commands and unknown input', () => {
  for (const value of [null, {}, { ...input, client: 'radxa' }, { ...input, firewallBackend: 'auto' },
    { ...input, schema: 2 }, { ...input, root: '/tmp' }, { ...input, command: '/bin/sh' }]) assert.throws(() => compileDnsControllerServicePlan(value));
});
