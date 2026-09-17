import { test } from 'node:test';
import assert from 'node:assert/strict';
import { currentSSID, validateJobId, wifiInterface, withTemporaryWifi } from '../scripts/perf-ap-managed.mjs';
import { copyTar, validateCollectedState } from '../scripts/remote-collect.mjs';
import { macRepo, macJobDir, remotePort } from '../scripts/remote-mac.mjs';
import { main as startRemoteAP } from '../scripts/remote-ap-test.mjs';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test('Mac Wi-Fi hardware and SSID parsing', () => {
  const hardware = 'Hardware Port: Ethernet\nDevice: en4\nEthernet Address: a\n\nHardware Port: Wi-Fi\nDevice: en1\nEthernet Address: b\n';
  assert.equal(wifiInterface(hardware), 'en1');
  assert.equal(currentSSID('Current Wi-Fi Network: Home Network\n'), 'Home Network');
  assert.equal(currentSSID('You are not associated with an AirPort network.\n'), null);
  assert.throws(() => wifiInterface('Hardware Port: Ethernet\nDevice: en4\n'));
});

test('managed Wi-Fi switches back after the run fails', async () => {
  const calls = [];
  const runError = Error('iperf failed');
  const outcome = await withTemporaryWifi({previous: 'Home', ap: 'MeshPN',
    join: async ssid => calls.push(`join ${ssid}`), wait: async ssid => calls.push(`wait ${ssid}`),
    run: async () => {calls.push('run'); throw runError;},
    restore: async ssid => calls.push(`restore ${ssid}`),
  });
  assert.deepEqual(calls, ['join MeshPN', 'wait MeshPN', 'run', 'restore Home', 'wait Home']);
  assert.equal(outcome.error, runError);
  assert.equal(outcome.restoreError, undefined);
});

test('managed Wi-Fi also restores when joining AP fails after a network change', async () => {
  const calls = [];
  const outcome = await withTemporaryWifi({previous: 'Home', ap: 'MeshPN',
    join: async () => {calls.push('join'); throw Error('join failed');},
    wait: async () => {calls.push('wait');}, run: async () => {calls.push('run');},
    restore: async () => {calls.push('restore');},
  });
  assert.deepEqual(calls, ['join', 'restore', 'wait']);
  assert.equal(outcome.error.message, 'join failed');
});

test('managed Wi-Fi leaves the already-selected AP alone', async () => {
  const outcome = await withTemporaryWifi({previous: 'MeshPN', ap: 'MeshPN',
    join: async () => {throw Error('unexpected join');},
    wait: async () => {throw Error('unexpected wait');},
    run: async () => 42,
    restore: async () => {throw Error('unexpected restore');},
  });
  assert.equal(outcome.result, 42);
  assert.equal(outcome.switched, false);
});

test('remote paths and received state are constrained to a job ID', () => {
  const id = '2026-09-17T123456Z-abcdef12';
  assert.equal(validateJobId(id), id);
  assert.throws(() => validateJobId('../other'));
  assert.equal(macRepo('/Users/mac user/meshpn'), "'/Users/mac user/meshpn'");
  assert.equal(macJobDir(id).endsWith(`/device/perf-managed-results/${id}`), true);
  assert.throws(() => macRepo('relative/repo'));
  assert.equal(remotePort('22022'), '22022');
  assert.throws(() => remotePort('22'));
  assert.equal(validateCollectedState(id, {id, phase: 'completed', report: 'perf/2026-09-17-run/report.md'}).phase, 'completed');
  assert.throws(() => validateCollectedState(id, {id, phase: 'completed', report: 'perf/../../outside/report.md'}));
});

test('Linux AP orchestrator starts one detached Mac job and passes only its ID to collector', async () => {
  const id = '2026-09-17T123456Z-abcdef12';
  let command, collected;
  await startRemoteAP(['user@example.test'], {
    run: async (bin, args) => {command = {bin, args}; return {code: 0, stdout: `${id}\n`, stderr: ''};},
    collectJob: async (...args) => {collected = args;}, announce: () => {},
  });
  assert.equal(command.bin, 'ssh');
  assert.match(command.args.at(-1), /device:perf:ap-managed/);
  assert.match(command.args.at(-1), /--ap-tcp-paced/);
  assert.equal(collected[0], id);
  assert.equal(collected[2], 360);
  await assert.rejects(() => startRemoteAP(['bad;target'], {
    run: async () => {throw Error('should not launch');}, announce: () => {},
  }));
});

test('collector transfers the job tree as files without reading log contents', async () => {
  const root = await mkdtemp(join(tmpdir(), 'meshpn-collector-test-'));
  const id = '2026-09-17T123456Z-abcdef12';
  try {
    const source = join(root, 'mac'), staging = join(root, 'staging');
    await mkdir(join(source, id), {recursive: true}); await mkdir(staging);
    await writeFile(join(source, id, 'worker.log'), 'sensitive raw diagnostic bytes\n');
    let remoteCommand;
    await copyTar(id, 'macuser', staging, {start: (bin, args, options) => {
      if (bin === 'ssh') {
        remoteCommand = args.at(-1);
        return spawn('tar', ['-cf', '-', '-C', source, id], options);
      }
      return spawn(bin, args, options);
    }});
    assert.match(remoteCommand, /tar -C .* -cf - '2026-09-17T123456Z-abcdef12'/);
    assert.equal(await readFile(join(staging, id, 'worker.log'), 'utf8'), 'sensitive raw diagnostic bytes\n');
  } finally {await rm(root, {recursive: true, force: true});}
});
