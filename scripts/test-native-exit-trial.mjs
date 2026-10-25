import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import { validateDirectExitConfig, exitRecoveryAllowed, exitTrialUnitArgs, exitEndpointRouteMatches, assertStandaloneExitState } from './clean-vpn-native-exit-trial.mjs';

test('owned exit endpoint uses the kernel local route, not a remote uplink route', () => {
  const row = { type: 'local', dst: '154.62.226.216', dev: 'lo', prefsrc: '154.62.226.216' };
  assert.equal(exitEndpointRouteMatches([row], row.dst), true);
  for (const routes of [[], [row, row], [{ ...row, type: 'unicast' }], [{ ...row, dev: 'eth0' }], [{ ...row, dst: '1.1.1.1' }]])
    assert.equal(exitEndpointRouteMatches(routes, row.dst), false);
});
test('standalone trial refuses active services, occupied listener and existing VPN state', () => {
  const state = { ActiveState: 'inactive', MainPID: '0' };
  assert.doesNotThrow(() => assertStandaloneExitState(state, '', [{ ifname: 'eth0' }], [{ dst: 'default', dev: 'eth0' }]));
  for (const args of [[{ ...state, ActiveState: 'active' }, '', [], []], [{ ...state, MainPID: '23' }, '', [], []],
    [state, 'LISTEN', [], []], [state, '', [{ ifname: 'tun0' }], []], [state, '', [], [{ dst: '10.99.0.0/24' }]]])
    assert.throws(() => assertStandaloneExitState(...args));
  const args = exitTrialUnitArgs({ node: '/usr/bin/node', script: '/trial.mjs', config: '/config.json', endpoint: '154.62.226.216', uplink: 'eth0', holdSeconds: 60, standalone: true });
  assert.ok(args.includes('--standalone'));
  assert.ok(args.includes('--property=ExecStopPost=/usr/bin/node /trial.mjs --recover --standalone'));
});

const legacy = { cert: '/root/certs/fullchain.pem', key: '/root/certs/privkey.pem',
  secret: '/root/certs/clean-vpn-hmac.key', publicName: 'cover.example' };
const config = { version: 1, transport: 'combo-tls', role: 'exit',
  boring: { version: 1, role: 'exit', address: '154.62.226.216', port: 443, tun: 'tun0', cert: legacy.cert, key: legacy.key,
    peers: [{ ipv4: '10.99.0.2', secret_path: legacy.secret }] },
  transparent: { version: 1, transport: 'transparent-tls', role: 'exit', public_name: 'cover.example',
    secret_path: '/root/native/relay.psk', listen: { ipv4: '154.62.226.216', port: 443 },
    destination_policy: { mode: 'public-https', deny_ipv4: [] }, replay_directory: '/var/lib/native/replay' } };

test('direct exit config is bound to the running legacy material and one public listener', () => {
  assert.deepEqual(validateDirectExitConfig(config, { endpoint: '154.62.226.216', uplink: 'eth0', legacy }), config);
  for (const changed of [
    { ...config, role: 'client' },
    { ...config, boring: { ...config.boring, address: '203.0.113.1' } },
    { ...config, boring: { ...config.boring, cert: '/other' } },
    { ...config, transparent: { ...config.transparent, public_name: 'other.example' } },
    { ...config, transparent: { ...config.transparent, listen: { ipv4: '0.0.0.0', port: 443 } } },
  ]) assert.throws(() => validateDirectExitConfig(changed, { endpoint: '154.62.226.216', uplink: 'eth0', legacy }));
});

test('transient unit has a deadline, whole-cgroup stop and independent exact recovery', () => {
  const args = exitTrialUnitArgs({ node: '/usr/bin/node', script: '/root/dev/meshpn/scripts/clean-vpn-native-exit-trial.mjs',
    config: '/root/native/exit.json', endpoint: '154.62.226.216', uplink: 'eth0', holdSeconds: 900 });
  assert.ok(args.includes('--property=KillMode=control-group'));
  assert.ok(args.includes('--property=RuntimeMaxSec=1080'));
  assert.ok(args.includes('--property=ExecStopPost=/usr/bin/node /root/dev/meshpn/scripts/clean-vpn-native-exit-trial.mjs --recover'));
  assert.ok(!args.some(value => /flush|iptables-restore|enable|disable|reboot/i.test(value)));
  assert.throws(() => exitTrialUnitArgs({ node: '/bad path/node', script: '/x', config: '/y', endpoint: '154.62.226.216', uplink: 'eth0', holdSeconds: 60 }));
});

test('recovery runs for idle units and the exact ExecStopPost invocation only', () => {
  const base = { LoadState: 'loaded', ActiveState: 'deactivating', SubState: 'stop-post', MainPID: '0', InvocationID: 'trial-id' };
  assert.equal(exitRecoveryAllowed(base, 'trial-id'), true);
  assert.equal(exitRecoveryAllowed({ ...base, ActiveState: 'failed' }, 'trial-id'), true);
  assert.equal(exitRecoveryAllowed({ ...base, ActiveState: 'active', SubState: 'running', MainPID: '123' }, 'trial-id'), false);
  assert.equal(exitRecoveryAllowed(base, 'foreign-id'), false);
  assert.equal(exitRecoveryAllowed({ ...base, ActiveState: 'inactive', SubState: 'dead', InvocationID: '' }), true);
  assert.equal(exitRecoveryAllowed({ ...base, ActiveState: 'failed', SubState: 'failed', MainPID: '0' }), true);
  assert.equal(exitRecoveryAllowed({ ...base, ActiveState: 'failed', SubState: 'failed', MainPID: '123' }), false);
});

test('exit trial CLI imports without action and help documents recovery', () => {
  const file = new URL('./clean-vpn-native-exit-trial.mjs', import.meta.url);
  const imported = spawnSync(process.execPath, ['--input-type=module', '-e', `await import(${JSON.stringify(file.href)})`], { encoding: 'utf8' });
  assert.equal(imported.status, 0, imported.stderr); assert.equal(imported.stdout, '');
  const help = spawnSync(process.execPath, [fileURL(file), '--help'], { encoding: 'utf8' });
  assert.equal(help.status, 0, help.stderr); assert.match(help.stdout, /--preflight\|--apply/); assert.match(help.stdout, /--recover/);
});

function fileURL(url) { return fs.realpathSync(url); }
