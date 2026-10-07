import test from 'node:test';
import assert from 'node:assert/strict';
import { nativeServiceUnit } from './lib/native-service-unit.mjs';
const options = { binary: '/opt/clean-vpn/clean-vpn-engine', config: '/etc/clean-vpn/client.json',
  networkUnit: 'clean-vpn-network.service', guardUnit: 'clean-vpn-guard.service' };
test('native service is direct, notified, bounded and tied to independent protection', () => {
  const unit = nativeServiceUnit(options);
  for (const line of ['Type=notify', 'NotifyAccess=main', 'StandardInput=null', 'Restart=on-failure',
    'KillMode=control-group', 'MemoryMax=256M', 'NoNewPrivileges=yes',
    'BindsTo=clean-vpn-network.service clean-vpn-guard.service',
    'ExecStart=/opt/clean-vpn/clean-vpn-engine --config /etc/clean-vpn/client.json --service'])
    assert.ok(unit.split('\n').includes(line), line);
  assert.doesNotMatch(unit, /node|ExecStop|iptables|sysctl|\/bin\/sh|--test-packet-fd/);
});
test('native unit rejects systemd specifier, command and dependency injection', () => {
  for (const p of ['', '/', 'relative', '/a/../b', '/a//b', '/a b', '/a%p', '/a\nb', '/a;id', '/a$X'])
    for (const field of ['binary', 'config']) assert.throws(() => nativeServiceUnit({ ...options, [field]: p }));
  for (const unit of ['', 'x.target', 'x.service y.service', 'x@a.service', 'x.service\nExecStart=id'])
    for (const field of ['networkUnit', 'guardUnit']) assert.throws(() => nativeServiceUnit({ ...options, [field]: unit }));
  assert.throws(() => nativeServiceUnit({ ...options, networkUnit: options.guardUnit }));
});
test('transparent direct service has no TUN privileges and only explicit replay write access', () => {
  const client = nativeServiceUnit({ ...options, transport: 'transparent-tls' });
  assert.ok(!client.includes('DeviceAllow=')); assert.ok(!client.includes('CAP_NET_ADMIN'));
  assert.ok(!client.includes('ReadWritePaths='));
  const exit = nativeServiceUnit({ ...options, transport: 'transparent-tls', replayDirectory: '/opt/native/exit/replay' });
  assert.match(exit, /ReadWritePaths=\/opt\/native\/exit\/replay\n/);
  assert.match(exit, /ProtectSystem=strict/); assert.doesNotMatch(exit, /--init-transparent-replay/);
  for (const replayDirectory of ['/', '/opt/../etc', '/opt/a b', '/opt/%n', '/opt/a\nExecStart=id'])
    assert.throws(() => nativeServiceUnit({ ...options, transport: 'transparent-tls', replayDirectory }));
  assert.throws(() => nativeServiceUnit({ ...options, replayDirectory: '/opt/replay' }));
});
