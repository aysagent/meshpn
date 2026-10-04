import test from 'node:test';
import assert from 'node:assert/strict';
import { assertUsbPmtuEvidence, pmtuCases, runUsbPmtu } from './lib/usb-pmtu-vm.mjs';
import { spawnSync } from 'node:child_process';
import { usbSoakInitialChecks, usbReadyChecks } from './lib/usb-e2e-evidence.mjs';

const bootId = '00000000-0000-0000-0000-000000000000';
const valid = () => ({ scenario: 'usb-pmtu', nic: 'none', hostSharedFilesystem: false, realTls: true, realTun: true, persistentInstalledFiles: true,
  boots: [{ phase: 0, bootId, code: 0, synced: true, unmounted: true, powerDown: true, kernelRestart: false, events: [
    { event: 'prepared', phase: 0, restored: false, uplinkDown: true }, { event: 'lifecycle-ready', phase: 0 },
    ...usbSoakInitialChecks().map(name => ({ event: 'check', phase: 0, name })),
    ...pmtuCases().map(([label, who, tx, rx, df, rdf], i) => {
      const id = i + 1, blocked = ['stopped', 'lower-path-df'].includes(label) || label === 'df-upload' && tx > 1372;
      const ok = !blocked && label !== 'df-download';
      return { event: 'pmtu', phase: 0, label, who, tx, rx, df, rdf,
        rows: [{ event: 'request', id, bytes: tx, hash: 123 }, { event: 'result', id, ok, bytes: ok ? rx : 0, hash: 234, expectedHash: 234, pathMtu: label === 'lower-path-df' ? 1280 : 1400 },
          ...(label === 'lower-path-df' ? [{ event: 'error', id, errno: 90, origin: 2, type: 3, code: 4, mtu: 1280 }] : []),
          ...(label === 'df-upload' && blocked ? [{ event: 'error', id, errno: 90,
            origin: who === 'peer' && tx <= 1472 ? 2 : 1, type: 3, code: 4,
            mtu: who === 'peer' && tx > 1472 ? 1500 : 1400 }] : [])],
        received: blocked ? [] : [{ event: 'received', id, peer: '154.62.226.216', valid: true, bytes: tx, hash: 123 },
          ...(label === 'df-download' ? [{ event: 'error', id, errno: 90, type: 3, code: 4, mtu: 1400 }] : [])] };
    }),
    { event: 'pmtu-counters', phase: 0,
      before: Object.fromEntries(['host', 'exit', 'peer'].map(w => [w, 'Ip: FragCreates ReasmOKs\nIp: 0 0\n'])),
      after: Object.fromEntries(['host', 'exit', 'peer'].map(w => [w, 'Ip: FragCreates ReasmOKs\nIp: 10 10\n'])) },
    ...['PMTU idle outer connection closed', 'PMTU stopped TUN removed', 'PMTU stopped SSH 22 and 2222', ...usbReadyChecks, 'PMTU restarted SSH 22 and 2222'].map(name => ({ event: 'check', phase: 0, name })),
    { event: 'completed', phase: 0, bootId, pmtu: true },
  ] }] });
test('complete PMTU matrix accepted', () => assert.doesNotThrow(() => assertUsbPmtuEvidence(valid())));
test('local EMSGSIZE may have no quoted payload ID', () => {
  const r = valid(), e = r.boots[0].events.find(e => e.label === 'df-upload' && e.who === 'host' && e.tx === 1373);
  e.rows.find(r => r.event === 'error').id = 0;
  e.rows.find(r => r.event === 'result').sendErrno = 90;
  assert.doesNotThrow(() => assertUsbPmtuEvidence(r));
});
for (const [name, mutate] of Object.entries({
  missingSize: r => { const a = r.boots[0].events; a.splice(a.findIndex(e => e.label === 'upload'), 1); },
  duplicate: r => { const a = r.boots[0].events, i = a.findIndex(e => e.label === 'upload'); a[i + 1] = a[i]; },
  timeoutInsteadOfPmtu: r => { const e = r.boots[0].events.find(e => e.label === 'df-upload' && e.tx > 1372); e.rows.pop(); },
  corruptedData: r => { r.boots[0].events.find(e => e.label === 'upload').rows[1].hash++; },
  directBypass: r => { r.boots[0].events.find(e => e.label === 'upload').received[0].peer = '192.168.1.10'; },
  stoppedHit: r => { r.boots[0].events.find(e => e.label === 'stopped').received.push({ event: 'received', id: 49 }); },
  missingServerIcmp: r => { r.boots[0].events.find(e => e.label === 'df-download').received.pop(); },
  missingRescue: r => { r.boots[0].events = r.boots[0].events.filter(e => e.name !== 'PMTU stopped SSH 22 and 2222'); },
  failEvent: r => r.boots[0].events.unshift({ event: 'failed', phase: 0 }),
  noFragmentEvidence: r => { const c = r.boots[0].events.find(e => e.event === 'pmtu-counters'); c.after = c.before; },
  wrongMtu: r => { r.boots[0].events.find(e => e.label === 'df-upload' && e.who === 'peer' && e.tx === 1373).rows.at(-1).mtu = 1500; },
  unquotedNetworkError: r => { r.boots[0].events.find(e => e.label === 'df-upload' && e.who === 'peer' && e.tx === 1373).rows.at(-1).id = 0; },
  hostNetwork: r => { r.nic = 'user'; },
})) test('PMTU evidence rejects ' + name, () => { const r = valid(); mutate(r); assert.throws(() => assertUsbPmtuEvidence(r)); });
test('PMTU driver refuses host before commands', async () => assert.rejects(runUsbPmtu({}), /AssertionError/));
test('memory sampler refuses host before enabling GC or writing files', () => {
  const r = spawnSync(process.execPath, ['scripts/lib/usb-memory-vm.mjs'], { encoding: 'utf8', timeout: 10000 });
  assert.equal(r.status, 1); assert.match(r.stderr, /AssertionError/);
});
