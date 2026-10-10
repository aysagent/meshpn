import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { parseDirectConfigArgs, prepareDirectExit } from './clean-vpn-native-direct-config.mjs';

test('direct pair preparation requires explicit new absolute locations and endpoint', () => {
  const args = ['--create-exit', '--directory=/root/native-combo-trial', '--endpoint=154.62.226.216', '--uplink=eth0',
    '--client-relay-path=/root/native-combo-trial/relay.psk', '--deny-ipv4=203.0.113.0/24,198.51.100.0/24'];
  assert.deepEqual(parseDirectConfigArgs(args), { directory: '/root/native-combo-trial', endpoint: '154.62.226.216', uplink: 'eth0',
    clientRelayPath: '/root/native-combo-trial/relay.psk', denyIpv4: ['203.0.113.0/24', '198.51.100.0/24'] });
  for (const bad of [args.slice(1), [...args, '--endpoint=1.1.1.1'], args.map(v => v.replace('/root/native-combo-trial', 'relative')),
    args.map(v => v.replace('--uplink=eth0', '--uplink=bad interface')),
    args.map(v => v.replace('203.0.113.0/24,198.51.100.0/24', '8.8.8.1/24')),
    args.map(v => v.replace('203.0.113.0/24,198.51.100.0/24', '999.1.1.0/24'))]) assert.throws(() => parseDirectConfigArgs(bad));
  assert.deepEqual(parseDirectConfigArgs(['--help']), { help: true });
});

test('preparation creates separate private relay material and explicitly initializes replay', async t => {
  const base = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'direct-config-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const directory = path.join(base, 'new'), calls = [];
  const legacy = { cert: '/cert/fullchain.pem', key: '/cert/privkey.pem', secret: '/cert/packet.psk', publicName: 'cover.example' };
  const report = await prepareDirectExit({ directory, endpoint: '154.62.226.216', uplink: 'eth0',
    clientRelayPath: '/root/native-combo-trial/relay.psk', denyIpv4: [] }, {
    requireRoot: false, uid: () => process.getuid(), context: async () => ({ legacy }),
    execute(file, args) { calls.push([file, args]); return ''; },
  });
  assert.equal(report.status, 'prepared');
  assert.equal(fs.readFileSync(path.join(directory, 'relay.psk')).length, 32);
  assert.equal(fs.statSync(path.join(directory, 'relay.psk')).mode & 0o777, 0o600);
  const exit = JSON.parse(fs.readFileSync(path.join(directory, 'exit.json')));
  const client = JSON.parse(fs.readFileSync(path.join(directory, 'client-profile.json')));
  assert.equal(exit.boring.peers[0].secret_path, legacy.secret); assert.equal(exit.transparent.secret_path, path.join(directory, 'relay.psk'));
  assert.equal(client.relay_secret_path, '/root/native-combo-trial/relay.psk');
  assert.deepEqual(calls.map(([, args]) => args[0]), ['--check-config', '--init-transparent-replay']);
  await assert.rejects(() => prepareDirectExit({ directory, endpoint: '154.62.226.216', uplink: 'eth0',
    clientRelayPath: '/root/native-combo-trial/relay.psk', denyIpv4: [] }, { requireRoot: false,
    uid: () => process.getuid(), context: async () => ({ legacy }), execute() {} }), /EEXIST/);
});

test('preparation refuses a symlinked or foreign writable creation ancestor', async t => {
  const base = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'direct-config-parent-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const real = path.join(base, 'real'); fs.mkdirSync(real, { mode: 0o700 });
  const alias = path.join(base, 'alias'); fs.symlinkSync(real, alias);
  const legacy = { cert: '/cert/fullchain.pem', key: '/cert/privkey.pem', secret: '/cert/packet.psk', publicName: 'cover.example' };
  await assert.rejects(() => prepareDirectExit({ directory: path.join(alias, 'trial'), endpoint: '154.62.226.216', uplink: 'eth0',
    clientRelayPath: '/root/native-combo-trial/relay.psk', denyIpv4: [] }, { requireRoot: false,
    uid: () => process.getuid(), context: async () => ({ legacy }), execute() {} }), /unsafe creation ancestor/);
});
