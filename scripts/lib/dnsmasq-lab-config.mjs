/** Narrow Radxa fixture compiler. No host writer, daemon control or takeover authority. */
import assert from 'node:assert/strict';
import { filterDnsmasqDiagnostic } from './dnsmasq-config.mjs';

export function compileRadxaDnsmasqLabConfig(source, { port, normalizeDhcpDns = false } = {}) {
  assert.ok(typeof source === 'string' && Buffer.byteLength(source) <= 32768, 'bounded fixture required');
  assert.ok(Number.isInteger(port) && port >= 1024 && port <= 65535, 'adapter high port required');
  const parsed = filterDnsmasqDiagnostic(source);
  assert.equal(parsed.omitted + parsed.unparsed, 0, 'unsupported fixture syntax');
  const allowed = new Set(['interface', 'listen-address', 'dhcp-range', 'dhcp-option', 'server', 'no-resolv']);
  assert.ok(parsed.entries.every((e) => allowed.has(e.key)), 'includes and extra options require separate review');
  const values = (key) => parsed.entries.filter((e) => e.key === key).map((e) => e.value);
  assert.deepEqual(values('interface'), ['usb0']);
  assert.deepEqual(values('listen-address'), ['127.0.0.1,192.168.7.1']);
  assert.deepEqual(values('dhcp-range'), ['192.168.7.10,192.168.7.50,255.255.255.0,12h']);
  assert.deepEqual(values('no-resolv'), [undefined]);
  assert.deepEqual(values('server'), ['1.1.1.1', '8.8.8.8']);
  assert.deepEqual(values('dhcp-option'), ['3,192.168.7.1', '6,192.168.7.1', 'option:dns-server,1.1.1.1']);
  assert.equal(normalizeDhcpDns, true, 'explicit DHCP DNS normalization required');
  const entries = parsed.entries.filter((e) => e.key !== 'server'
    && !(e.key === 'dhcp-option' && /^(6|option:dns-server),/.test(e.value)));
  entries.push({ key: 'dhcp-option', value: '6,192.168.7.1' }, { key: 'server', value: `127.0.0.1#${port}` });
  return { scope: 'radxa-fixture-only', hostChangesAllowed: false, baseline: source,
    managed: entries.map((e) => e.value === undefined ? e.key : `${e.key}=${e.value}`).join('\n') + '\n' };
}
