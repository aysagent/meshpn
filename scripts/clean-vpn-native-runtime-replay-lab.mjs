#!/usr/bin/env node
// Compatibility extension: real production engine, experimental relays and a
// durable volume. No host interfaces, published ports or network access.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { cleanupLab } from './clean-vpn-native-runtime-cleanup.mjs';

const cli = JSON.parse(process.env.CVPN_CONTAINER_COMMAND ?? '["podman"]');
assert.ok(Array.isArray(cli) && cli.length && cli.every(x => typeof x === 'string'));
const image = process.env.CVPN_RUNTIME_IMAGE; assert.ok(image);
assert.equal(process.argv.length, 3, 'Usage: runtime-replay-lab NEW_REPORT.json');
const output = path.resolve(process.argv[2]); assert.equal(fs.existsSync(output), false);
const prefix = 'cvpnrt-' + randomBytes(8).toString('hex'), label = 'org.meshpn.native-runtime-lab=' + prefix;
const volume = prefix + '-replay';
const invoke = args => execFileSync(cli[0], [...cli.slice(1), ...args], { encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
const journal = { schema: 1, kind: 'native-runtime-lab-ownership', prefix, cli };
fs.writeFileSync(output + '.ownership.json', JSON.stringify(journal) + '\n', { flag: 'wx', mode: 0o600 });
const report = { schema: 1, kind: 'native-runtime-replay-compatibility', image, phases: [], status: 'failed',
  scope: 'experimental-engine-packaging-not-public-launcher-or-routing-acceptance' };
const worker = path.resolve('scripts/lib/native-runtime-replay-worker.mjs');
const wait = async (name, check) => {
  let error;
  for (let i = 0; i < 200; i++) {
    const logResult = spawnSync(cli[0], [...cli.slice(1), 'logs', name], { encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024 });
    assert.equal(logResult.status, 0, logResult.stderr);
    const logs = logResult.stdout + logResult.stderr;
    try { return check(logs); } catch (e) { error = e; }
    if (!JSON.parse(invoke(['inspect', name]))[0].State.Running) throw Error(logs + '\n' + error.message);
    await delay(100);
  }
  throw error;
};
try {
  const inspected = JSON.parse(invoke(['image', 'inspect', image]))[0];
  report.imageId = inspected.Id; report.architecture = inspected.Architecture;
  report.engineSha256 = invoke(['run', '--rm', '--network=none', '--entrypoint=sha256sum', image, '/usr/local/bin/clean-vpn-engine']).split(/\s+/)[0];
  // Read only: obtain the parent identity to refuse accidental host-netns use.
  const parent = invoke(['run', '--rm', '--network=host', '--entrypoint=readlink', image, '/proc/self/ns/net']).trim();
  assert.match(parent, /^net:\[\d+\]$/);
  invoke(['volume', 'create', '--label', label, volume]);
  for (const transport of ['transparent-tls', 'combo-tls']) {
    for (const phase of ['first', 'readonly', 'recreated']) {
      const name = prefix + '-' + transport + '-' + phase;
      invoke(['run', '-d', '--name', name, '--label', label, '--network=none', '--no-healthcheck',
        '--memory=128m', '--pids-limit=64', '--cap-drop=ALL', '--cap-add=NET_ADMIN', '--cap-add=NET_RAW',
        '--cap-add=SETUID', '--cap-add=SETGID', '--device=/dev/net/tun', '--security-opt=no-new-privileges',
        '--read-only', '--tmpfs=/run:rw,nosuid,nodev,mode=755', '--tmpfs=/tmp:rw,nosuid,nodev,mode=1777',
        '-v', volume + ':/state' + (phase === 'readonly' ? ':ro' : ''), '-v', worker + ':/fixture.mjs:ro',
        '-e', 'CVPN_PARENT_NETNS=' + parent, '--entrypoint=node', image, '/fixture.mjs', transport, phase]);
      const marker = phase === 'first' ? 'REPLAY_HOLD=' : 'REPLAY_REPORT=';
      const result = await wait(name, logs => {
        const line = logs.split('\n').find(l => l.startsWith(marker)); assert.ok(line, logs);
        return JSON.parse(line.slice(marker.length));
      });
      assert.equal(result.status, 'passed'); report.phases.push(result);
      if (phase === 'first') {
        invoke(['kill', '--signal=KILL', name]);
        const state = JSON.parse(invoke(['inspect', name]))[0].State;
        assert.equal(state.Running, false); assert.equal(state.ExitCode, 137);
      }
      else await wait(name, () => {
        const state = JSON.parse(invoke(['inspect', name]))[0].State;
        assert.equal(state.Running, false); assert.equal(state.ExitCode, 0);
      });
      invoke(['rm', name]); console.log('REPLAY_LAB=' + transport + ':' + phase);
    }
  }
  report.status = 'passed';
} catch (e) {
  report.error = e.message; process.exitCode = 1; console.error(e.message);
} finally {
  try { report.cleanup = cleanupLab(journal, invoke); }
  catch (e) { report.cleanup = { status: 'failed', error: e.message }; report.status = 'failed'; process.exitCode = 1; }
  fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
}
