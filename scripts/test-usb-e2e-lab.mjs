import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { runInNewContext } from 'node:vm';
import { usbE2eUnits } from './lib/usb-e2e-vm.mjs';
import { assertUsbE2eEvidence, usbE2eChecks, assertUsbFaultEvidence, usbFaultChecks } from './lib/usb-e2e-evidence.mjs';
import { runUsbFaultScenarios } from './lib/usb-fault-vm.mjs';

function report() {
  return { nic: 'none', hostSharedFilesystem: false, realTls: true, realTun: true, persistentInstalledFiles: true,
    boots: [0, 1].map(phase => {
      const bootId = `${phase}0000000-0000-0000-0000-000000000000`;
      return { phase, code: 0, synced: true, unmounted: true, kernelRestart: phase === 0, powerDown: phase === 1, bootId,
        events: [{ event: 'prepared', phase, restored: phase === 1, uplinkDown: true },
          ...usbE2eChecks(phase).map(name => ({ event: 'check', phase, name })),
          { event: 'lifecycle-ready', phase }, { event: 'completed', phase, bootId, usbDnsPolicy: 'cvks4-usb-tunnel-only' }] };
    }) };
}
test('complete ordered two-boot evidence is accepted', () => assert.doesNotThrow(() => assertUsbE2eEvidence(report())));
for (const [name, mutate] of Object.entries({
  missingDNS: r => { r.boots[0].events = r.boots[0].events.filter(e => e.name !== 'stopped DNS no upstream query 1.1.1.1/false/1'); },
  missingIPv6Baseline: r => { r.boots[0].events.splice(3, 1); },
  missingBoot: r => r.boots.pop(),
  sameBoot: r => { r.boots[1].bootId = r.boots[0].bootId; r.boots[1].events.at(-1).bootId = r.boots[0].bootId; },
  missingUnmount: r => { r.boots[1].unmounted = false; },
  noKernelReboot: r => { r.boots[0].kernelRestart = false; },
  preconfiguredUplink: r => { r.boots[0].events[0].uplinkDown = false; },
  missingRestore: r => { r.boots[1].events[0].restored = false; },
  unexpectedFailure: r => { r.boots[0].events.push({ phase: 0, event: 'failed' }); },
  sharedFilesystem: r => { r.hostSharedFilesystem = true; },
  bridgedNIC: r => { r.nic = 'tap'; },
  missingPrivateDNSProtection: r => { r.boots[0].events.at(-1).usbDnsPolicy = 'LAN-allowed'; },
  fakeTUN: r => { r.realTun = false; },
  duplicateCheck: r => { r.boots[0].events.splice(2, 0, r.boots[0].events[1]); },
  wrongPhase: r => { r.boots[1].events[1].phase = 0; },
})) test(`incomplete/unsafe evidence rejected: ${name}`, () => { const r = report(); mutate(r); assert.throws(() => assertUsbE2eEvidence(r)); });

for (const mode of ['prepare', 'fixture', 'probe', 'probe-worker', 'fault-monitor', 'run']) test(`guest ${mode} refuses host before mutations`, () => {
  assert.doesNotMatch(fs.readFileSync('/proc/cmdline', 'utf8'), /meshpn\.usb-e2e=1/);
  const result = spawnSync(process.execPath, ['scripts/lib/usb-e2e-vm.mjs', mode], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 1); assert.match(result.stderr, /AssertionError/);
  assert.doesNotMatch(result.stdout, /USB_E2E_EVENT/);
});
test('fault injection helper refuses host before using command callbacks', async () => {
  await assert.rejects(runUsbFaultScenarios({}), /AssertionError/);
});
function faultReport(networkOnly = false) {
  const r = report(); r.scenario = networkOnly ? 'usb-network-faults' : 'usb-faults'; r.boots = [r.boots[0]];
  const b = r.boots[0]; b.kernelRestart = false; b.powerDown = true;
  b.events = [b.events[0], ...usbFaultChecks(networkOnly).map(name => ({ event: 'check', phase: 0, name })),
    { event: 'lifecycle-ready', phase: 0 },
    ...[...(networkOnly ? [] : [['sigkill', 'begin'], ['sigkill', 'recovered']]), ...['exit-blackhole', 'carrier-loss'].flatMap(s => ['begin', 'restore', 'recovered'].map(a => [s, a]))]
      .map(([scenario, action]) => ({ event: 'fault', phase: 0, scenario, action, ...(action === 'restore' ? { elapsedMs: 120001 } : {}) })),
    { ...b.events.at(-1), faultScenarios: true }];
  return r;
}
test('full fault evidence with long outage and recovery is accepted', () => assert.doesNotThrow(() => assertUsbFaultEvidence(faultReport())));
test('network-only evidence never accepts a missing crash in full mode', () => {
  const r = faultReport(true); assert.doesNotThrow(() => assertUsbFaultEvidence(r));
  r.scenario = 'usb-faults'; assert.throws(() => assertUsbFaultEvidence(r));
});
for (const [name, mutate] of Object.entries({
  missingKill: r => { r.boots[0].events = r.boots[0].events.filter(e => e.name !== 'SIGKILL increments restart counter'); },
  shortOutage: r => { r.boots[0].events.find(e => e.action === 'restore').elapsedMs = 119999; },
  fakeDuration: r => { r.boots[0].events.find(e => e.action === 'restore').elapsedMs = Infinity; },
  missingRecovery: r => { r.boots[0].events = r.boots[0].events.filter(e => e.name !== 'carrier-loss recovers without VPN restart'); },
  missingReceiverAudit: r => { r.boots[0].events = r.boots[0].events.filter(e => e.name !== 'final dns no direct or LAN receiver hits'); },
  incompleteScenario: r => { r.boots[0].events = r.boots[0].events.filter(e => !(e.scenario === 'exit-blackhole' && e.action === 'recovered')); },
  incompletePoweroff: r => { r.boots[0].powerDown = false; },
  wrongMode: r => { r.scenario = 'two-boot-installation'; },
  extraFailure: r => { r.boots[0].events.push({ event: 'failed', phase: 0 }); },
})) test('fault evidence rejects ' + name, () => { const r = faultReport(); mutate(r); assert.throws(() => assertUsbFaultEvidence(r)); });
test('fixtures run real exit and DNS, default boot enables persisted installation', () => {
  const units = usbE2eUnits();
  assert.match(units['default.target'], /multi-user.target/);
  assert.match(units['usb-e2e-exit.service'], /NetworkNamespacePath=\/run\/netns\/exit/);
  assert.match(units['usb-e2e-exit.service'], /clean-vpn.js --role=exit --type=tls/);
  assert.match(units['usb-e2e-dns-relay.service'], /dnsmasq.*--no-resolv --server=192.168.1.1/);
  assert.ok(!units['clean-vpn.service']); // must come from actual installer, not a fixture
});
test('runner uses no external NIC or host shares and only newly allocated ext4 disk', () => {
  const s = fs.readFileSync(new URL('./clean-vpn-usb-e2e-lab.mjs', import.meta.url), 'utf8');
  assert.match(s, /'-nic', 'none'/); assert.match(s, /'-nodefaults', '-no-user-config'/);
  assert.doesNotMatch(s, /'-virtfs'|'-fsdev'|'-netdev'|'-device'|sudo/);
  assert.match(s, /fs\.openSync\(disk, 'wx', 0o600\)/);
  assert.match(s, /assertUsbE2eEvidence\(report\)/);
  assert.match(s, /MESHPN_LAB_NODE_HEADERS/);
  assert.match(s, /diagnostics \? instrumentTunMemory\(original\) : original/);
  assert.match(s, /report\.sourceHashes\[path\] = hash\(original\)/);
  assert.match(s, /report\.nativeBuild =/);
});
test('raw receiver preserves the actual accepted address after socket teardown, including bypass addresses', () => {
  const source = fs.readFileSync(new URL('./lib/usb-e2e-vm.mjs', import.meta.url), 'utf8');
  const callback = /const tcp = net\.createServer\((s => \{[\s\S]*?)\); tcp\.listen/.exec(source)?.[1];
  assert.ok(callback);
  for (const peer of ['154.62.226.216', '192.168.1.10', undefined]) {
    const records = [], socket = new EventEmitter(); socket.remoteAddress = peer;
    socket.end = () => {}; socket.destroy = () => { socket.remoteAddress = undefined; };
    const accept = runInNewContext(`(${callback})`, { Buffer,
      record: (data, address, protocol) => { records.push({ data: data.toString(), address, protocol }); return Buffer.from('ok'); } });
    accept(socket); socket.emit('data', Buffer.from('fixture-token'));
    socket.remoteAddress = undefined; socket.emit('end');
    assert.deepEqual(records, [{ data: 'fixture-token', address: peer, protocol: 'tcp' }]);
  }
});
