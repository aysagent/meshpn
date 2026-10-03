import assert from 'node:assert/strict';
import { isIPv4 } from 'node:net';
import { isAbsolute, resolve } from 'node:path';
import { tunnelDnsServers } from './dns-tunnel-forwarder.mjs';

export function cleanVpnDnsOptions(argv, { role, server }) {
  const found = {};
  for (const arg of argv) {
    const m = /^--dns-(mode|server|state-dir|usb)=(.*)$/.exec(arg); if (!m) continue;
    assert.ok(!Object.hasOwn(found, m[1]), `duplicate --dns-${m[1]}`); found[m[1]] = m[2];
  }
  if (role && role !== 'client') assert.equal(Object.keys(found).length, 0, 'client DNS options are not exit options');
  const mode = found.mode ?? (role === 'client' ? 'tunnel' : 'off');
  assert.ok(['tunnel', 'off', 'managed'].includes(mode), '--dns-mode=tunnel|off|managed');
  assert.notEqual(mode, 'managed', 'managed DNS integration is not ready for clean-vpn CLI; use the separate opt-in dns-client workflow, not an automatic host takeover');
  if (mode !== 'tunnel') assert.ok(found.server === undefined && found['state-dir'] === undefined, '--dns-server/--dns-state-dir require --dns-mode=tunnel');
  if (found.server !== undefined) tunnelDnsServers(found.server);
  if (found.usb !== undefined) {
    assert.equal(found.usb, '1', '--dns-usb supports only =1');
    assert.ok(role === 'client' && mode === 'tunnel', '--dns-usb=1 requires client tunnel DNS');
    assert.ok(argv.includes('--type=tls') && argv.includes('--split-default'), '--dns-usb requires native TLS split-default');
    assert.ok(!argv.some(a => /^--(?:from-tun|client-lan-)/.test(a)), '--dns-usb cannot mix with other ingress scopes');
  }
  if (found['state-dir'] !== undefined) assert.ok(isAbsolute(found['state-dir']) && resolve(found['state-dir']) === found['state-dir'], '--dns-state-dir requires an absolute normalized path');
  if (mode === 'tunnel' && server) {
    const m = /^(.+):(\d+)$/.exec(server);
    assert.ok(m && isIPv4(m[1]), 'tunnel DNS requires --server=IPv4:PORT to avoid a DNS bootstrap loop; set TLS name separately');
  }
  return { dnsMode: mode, dnsServer: found.server, dnsStateDir: found['state-dir'], ...(found.usb ? { dnsUsb: true } : {}) };
}

export function tunnelDnsUsbScope(links) {
  assert.equal(tunnelDnsLanInterface('192.168.7.0/24', links), 'usb0', 'USB DNS requires usb0');
  const usb = links.find(l => l.ifname === 'usb0');
  assert.ok(usb.addr_info.some(a => a.family === 'inet' && a.local === '192.168.7.1' && a.prefixlen === 24), 'USB DNS requires 192.168.7.1/24');
  return { fromTun: null, lanSubnet: '192.168.7.0/24', lanInterface: 'usb0' };
}

export function tunnelDnsLanInterface(subnet, links) {
  if (!subnet) return null;
  const [base, bits] = subnet.split('/'), n = (s) => s.split('.').reduce((a, b) => ((a << 8) | Number(b)) >>> 0, 0);
  assert.ok(isIPv4(base) && /^(?:[1-9]|[12][0-9]|3[0-2])$/.test(bits), 'invalid DNS LAN subnet');
  const mask = (0xffffffff << (32 - Number(bits))) >>> 0;
  const candidates = links.filter((l) => l.ifname !== 'lo' && !/^tun/i.test(l.ifname) && (l.addr_info ?? []).some((a) =>
    a.family === 'inet' && isIPv4(a.local) && (n(a.local) & mask) === (n(base) & mask)));
  assert.equal(candidates.length, 1, 'DNS LAN scope requires exactly one interface in --client-lan-subnet');
  return candidates[0].ifname;
}
