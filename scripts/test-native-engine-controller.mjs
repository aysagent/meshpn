import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { NativeEngineController } from './lib/native-engine-controller.mjs';

function fixture() {
  const child = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() });
  const killed = []; child.kill = signal => killed.push(signal);
  const ctl = new NativeEngineController({ binary: '/lab/engine', config: '/lab/config.json', spawnChild: (exe, argv, opts) => {
    assert.equal(exe, '/lab/engine'); assert.deepEqual(argv, ['--config', '/lab/config.json']);
    assert.deepEqual(opts.stdio, ['pipe', 'pipe', 'pipe']); return child;
  } });
  return { ctl, child, killed };
}
const status = { version: 1, event: 'state', state: 'ready', generation: 0, tx_packets: 3, rx_packets: 2, dropped_packets: 0 };
test('controller accepts only bounded metadata and issues only control commands', () => {
  const { ctl, child } = fixture(); let got; ctl.on('status', s => got = s);
  const line = JSON.stringify(status); child.stdout.write(line.slice(0, 9)); assert.equal(got, undefined);
  child.stdout.write(line.slice(9) + '\n'); assert.deepEqual(got, status);
  ctl.status(); ctl.uplink(false); ctl.stop();
  assert.equal(child.stdin.read().toString(), '{"op":"status"}\n{"op":"uplink","ready":false}\n{"op":"stop"}\n');
  assert.equal(ctl.sendPacket, undefined); child.emit('close', 0, null);
});
for (const bad of [{ ...status, payload: 'forbidden' }, { ...status, tx_packets: -1 }, { ...status, state: 'secret value' }, 'x'.repeat(65537)]) {
  test('controller refuses malformed or excessive child output', () => {
    const { ctl, child, killed } = fixture(); let fault; ctl.on('fault', e => fault = e);
    child.stdout.write(typeof bad === 'string' ? bad : JSON.stringify(bad) + '\n');
    assert.deepEqual(killed, ['SIGKILL']); assert.equal(fault.reason, 'engine_control_protocol'); child.emit('close', null, 'SIGKILL');
  });
}
