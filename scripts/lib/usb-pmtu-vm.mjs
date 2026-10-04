/** Lab-only IPv4 UDP matrix across real TLS/TUN. Never changes the host. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { usbSoakInitialChecks, usbReadyChecks } from './usb-e2e-evidence.mjs';
const exec = promisify(execFile);
export const pmtuSizes = [1200, 1372, 1373, 1472, 1473, 4096];
export const pmtuCases = () => [
  ...pmtuSizes.map(size => ['control', 'exit', size, size, 0, 0]),
  ['cold-udp', 'peer', 1200, 1200, 0, 0],
  ...['host', 'peer'].flatMap(who => pmtuSizes.flatMap(size => [
    ['upload', who, size, 64, 0, 0], ['download', who, 64, size, 0, 0], ['df-upload', who, size, 64, 3, 0],
  ])),
  ...['host', 'peer'].flatMap(who => [['df-download', who, 64, 1472, 0, 3],
    ['reduced-download', who, 64, 1372, 0, 3], ['reduced-upload', who, 1372, 64, 2, 0]]),
  ...['host', 'peer'].flatMap(who => [['lower-path-df', who, 1372, 64, 3, 0],
    ['lower-path-reduced', who, 1252, 1252, 2, 0], ['lower-path-fragmented', who, 4096, 4096, 0, 0]]),
  ...pmtuSizes.map(size => ['stopped', 'peer', size, size, 0, 0]),
  ['restarted', 'peer', 4096, 4096, 0, 0],
];
const binary = '/usr/bin/usb-pmtu-probe';
export async function runUsbPmtu(c) {
  assert.match(fs.readFileSync('/proc/cmdline', 'utf8'), /(?:^|\s)meshpn.usb-pmtu=1(?:\s|$)/);
  assert.equal(fs.readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8').trim(), 'QEMU');
  assert.equal(process.getuid(), 0);
  const { check, event, ctl, ready, login, hits, ip, at, peerProbe, until, sync } = c;
  const counters = () => ({ host: fs.readFileSync('/proc/net/snmp', 'utf8'),
    exit: at('exit', 'cat', '/proc/net/snmp'), peer: at('peer', 'cat', '/proc/net/snmp') });
  const beforeCounters = counters();
  let id = 0;
  const probe = async (label, who, tx, rx, df = 0, rdf = 0) => {
    if (!['control', 'stopped', 'cold-udp'].includes(label)) assert.equal((await peerProbe({ host: '1.0.0.1' })).peer, '154.62.226.216', 'warm tunnel before PMTU measurement');
    const current = ++id;
    const args = ['probe', '1.0.0.1', who === 'host' ? '10.99.0.2' : '0.0.0.0', String(tx), String(rx), String(df), String(rdf), String(current)];
    const r = await exec(who === 'host' ? binary : '/usr/bin/ip', who === 'host' ? args : ['netns', 'exec', who, binary, ...args], { timeout: 15000 });
    const rows = r.stdout.trim().split('\n').map(x => JSON.parse(x));
    const result = rows.find(r => r.event === 'result'); assert.ok(result);
    const received = hits('/run/e2e-pmtu-hits').filter(r => r.id === current);
    event({ event: 'pmtu', phase: 0, label, who, tx, rx, df, rdf, rows, received });
    return result;
  };
  // Independent direct positive controls remain inside the isolated VM.
  for (const size of pmtuSizes) await probe('control', 'exit', size, size);
  await delay(10000);
  const outerSockets = () => sync('ss', ['-Htn', 'state', 'established', 'dst', '154.62.226.216', 'dport', '=', '443']);
  await until(() => !outerSockets(), 'outer TLS must really close before cold UDP', 30000);
  check('PMTU idle outer connection closed', !outerSockets());
  await probe('cold-udp', 'peer', 1200, 1200);
  for (const who of ['host', 'peer']) for (const size of pmtuSizes) {
    await probe('upload', who, size, 64);
    await probe('download', who, 64, size);
    await probe('df-upload', who, size, 64, 3);
  }
  for (const who of ['host', 'peer']) {
    await probe('df-download', who, 64, 1472, 0, 3);
    await probe('reduced-download', who, 64, 1372, 0, 3);
    await probe('reduced-upload', who, 1372, 64, 2);
  }
  // Affect only the synthetic origin route in the EXIT namespace. Outer TLS
  // routing and the client guard are untouched. Error must traverse TLS/NAT.
  const route = ['1.0.0.1/32', 'via', '154.62.226.1', 'dev', 'eth0', 'mtu', '1280'];
  at('exit', 'ip', 'route', 'add', ...route);
  try {
    for (const who of ['host', 'peer']) {
      await probe('lower-path-df', who, 1372, 64, 3);
      await probe('lower-path-reduced', who, 1252, 1252, 2);
      await probe('lower-path-fragmented', who, 4096, 4096);
    }
  } finally { at('exit', 'ip', 'route', 'del', ...route); }
  event({ event: 'pmtu-counters', phase: 0, before: beforeCounters, after: counters() });
  await ctl('stop', 'clean-vpn.service');
  check('PMTU stopped TUN removed', !JSON.parse(ip('-j', 'link', 'show')).some(i => i.ifname === 'tun0'));
  for (const size of pmtuSizes) await probe('stopped', 'peer', size, size);
  check('PMTU stopped SSH 22 and 2222', await login('22') && await login());
  await ctl('start', 'clean-vpn.service'); await ready();
  await probe('restarted', 'peer', 4096, 4096);
  check('PMTU restarted SSH 22 and 2222', await login('22') && await login());
}

export function assertUsbPmtuEvidence(r) {
  assert.equal(r.scenario, 'usb-pmtu'); assert.equal(r.nic, 'none'); assert.equal(r.hostSharedFilesystem, false);
  assert.equal(r.realTls, true); assert.equal(r.realTun, true); assert.equal(r.boots.length, 1);
  const b = r.boots[0]; assert.equal(b.code, 0); assert.equal(b.synced, true); assert.equal(b.unmounted, true); assert.equal(b.powerDown, true);
  assert.equal(r.persistentInstalledFiles, true); assert.equal(b.phase, 0); assert.equal(b.kernelRestart, false);
  assert.match(b.bootId, /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
  assert.deepEqual(b.events[0], { event: 'prepared', phase: 0, restored: false, uplinkDown: true });
  assert.deepEqual(b.events.filter(e => e.event === 'check').map(e => e.name), [...usbSoakInitialChecks(),
    'PMTU idle outer connection closed', 'PMTU stopped TUN removed', 'PMTU stopped SSH 22 and 2222', ...usbReadyChecks, 'PMTU restarted SSH 22 and 2222']);
  const rows = b.events.filter(e => e.event === 'pmtu');
  assert.deepEqual(rows.map(e => [e.label, e.who, e.tx, e.rx, e.df, e.rdf]), pmtuCases());
  assert.ok(b.events.every(e => e.phase === 0 && ['prepared', 'check', 'lifecycle-ready', 'pmtu', 'pmtu-counters', 'completed'].includes(e.event)));
  for (const k of ['prepared', 'lifecycle-ready', 'pmtu-counters', 'completed']) assert.equal(b.events.filter(e => e.event === k).length, 1);
  for (const name of ['PMTU stopped TUN removed', 'PMTU stopped SSH 22 and 2222', 'PMTU restarted SSH 22 and 2222']) assert.equal(b.events.filter(e => e.event === 'check' && e.name === name).length, 1);
  for (const e of rows) {
    const result = e.rows.find(r => r.event === 'result');
    assert.equal(e.rows.filter(r => r.event === 'result').length, 1);
    assert.equal(e.rows.filter(r => r.event === 'request').length, 1);
    assert.equal(result.id, rows.indexOf(e) + 1);
    // Local EMSGSIZE carries no quoted payload; its socket is exclusive to
    // this single probe, unlike received network ICMP which must quote the ID.
    assert.ok(e.rows.every(r => r.id === result.id || r.event === 'error' && r.id === 0 && r.origin === 1 && r.errno === 90 && result.sendErrno === 90));
    assert.ok(e.received.every(r => r.id === result.id));
    const seen = e.received.filter(r => r.event === 'received');
    const request = e.rows.find(r => r.event === 'request');
    assert.equal(request.bytes, e.tx);
    for (const s of seen) {
      assert.equal(s.valid, true); assert.equal(s.bytes, e.tx); assert.equal(s.hash, request.hash);
      assert.equal(s.peer, '154.62.226.216');
    }
    const positive = !['stopped', 'df-download', 'lower-path-df'].includes(e.label) && !(e.label === 'df-upload' && e.tx > 1372);
    assert.equal(result.ok, positive, `${e.label}/${e.who}/${e.tx}/${e.rx}`);
    if (positive) {
      assert.equal(result.bytes, e.rx); assert.equal(result.hash, result.expectedHash);
      assert.equal(seen.length, 1); assert.equal(seen[0].valid, true); assert.equal(seen[0].bytes, e.tx);
      assert.equal(seen[0].hash, e.rows.find(r => r.event === 'request').hash);
      if (e.label !== 'control') assert.equal(seen[0].peer, '154.62.226.216');
    } else if (e.label === 'df-download') {
      assert.equal(seen.length, 1);
      assert.ok(e.received.some(r => r.event === 'error' && r.errno === 90 && r.type === 3 && r.code === 4 && r.mtu === 1400), 'server must receive PMTU ICMP');
    } else {
      assert.equal(seen.length, 0, 'blocked/oversized datagram must not reach origin');
      if (e.label === 'lower-path-df') {
        assert.ok(e.rows.some(r => r.event === 'error' && r.errno === 90 && r.origin === 2 && r.type === 3 && r.code === 4 && r.mtu === 1280), 'PMTU error must return through the tunnel and NAT');
        assert.equal(result.pathMtu, 1280);
      }
      if (e.label === 'df-upload') {
        const networkError = e.who === 'peer' && e.tx <= 1472;
        assert.ok(e.rows.some(r => r.event === 'error' && r.errno === 90 &&
          (networkError ? r.origin === 2 && r.type === 3 && r.code === 4 && r.mtu === 1400 : r.origin === 1 && r.mtu === (e.who === 'host' ? 1400 : 1500))), 'client must receive correct EMSGSIZE/PMTU');
      }
    }
  }
  assert.equal(b.events.at(-1).event, 'completed'); assert.equal(b.events.at(-1).pmtu, true);
  assert.equal(b.events.at(-1).bootId, b.bootId);
  const count = b.events.find(e => e.event === 'pmtu-counters');
  const ipCounts = text => {
    const lines = text.split('\n').filter(l => l.startsWith('Ip:'));
    assert.equal(lines.length, 2);
    const keys = lines[0].trim().split(/\s+/).slice(1), values = lines[1].trim().split(/\s+/).slice(1).map(Number);
    assert.equal(keys.length, values.length); assert.ok(values.every(Number.isFinite));
    return Object.fromEntries(keys.map((k, i) => [k, values[i]]));
  };
  for (const counter of ['FragCreates', 'ReasmOKs']) {
    const increase = ['host', 'exit', 'peer'].reduce((sum, who) => sum + ipCounts(count.after[who])[counter] - ipCounts(count.before[who])[counter], 0);
    assert.ok(increase > 0, counter + ' must have real kernel evidence');
  }
}
