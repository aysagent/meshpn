/** Opt-in, fixed USB profile only. Lifetime journal locks belong to the caller. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { dirname } from 'node:path';
import { runTunnelDnsCommand } from './dns-tunnel-command.mjs';

export const usbRecoveryProfile = o => Boolean(o.dnsUsb && o.role === 'client' && o.type === 'tls'
  && o.splitDefault && o.ipv6 === 'auto' && o.dnsMode === 'tunnel'
  && o.server === '154.62.226.216:443' && !o.fromTun && !o.clientLanSubnet && !o.dnsStateDir);
const pending = j => j?.state && j.state.stage !== 'released';

export function verifyUsbRecoveryGuard(lockDescriptors) {
  const file = '/usr/local/bin/clean-vpn-killswitch.sh';
  for (let p = file; ; p = dirname(p)) {
    const s = fs.lstatSync(p);
    assert.ok(!s.isSymbolicLink() && s.uid === 0 && !(s.mode & 0o022)
      && (p === file ? s.isFile() && s.nlink === 1 : s.isDirectory()), `unsafe recovery guard: ${p}`);
    if (p === '/') break;
  }
  assert.equal(fs.readFileSync(file, 'utf8'), fs.readFileSync(new URL('../autostart/killswitch.sh', import.meta.url), 'utf8'),
    'installed recovery guard differs; explicit recovery required');
  const result = runTunnelDnsCommand(file, ['status'], { lockDescriptors, timeoutMs: 15000 }).trim();
  assert.equal(result, [4, 6].map(f => `[clean-vpn-killswitch] IPv${f}: cvks4:both:block:tun0:154.62.226.216:22`).join('\n'),
    'strict persistent USB guard required for recovery');
}

export function recoverUsbClient({ host, ipv6, dns, scope, verifyGuard = verifyUsbRecoveryGuard,
  links = locks => JSON.parse(runTunnelDnsCommand('ip', ['-j', 'link', 'show'], { lockDescriptors: locks })),
  log = console.log }) {
  if (![host, ipv6, dns].some(pending)) return false;
  assert.ok(host && ipv6 && dns, 'all recovery locks required');
  const locks = [host, ipv6, dns].flatMap(j => j.lockDescriptors);
  assert.deepEqual(scope, { fromTun: null, lanSubnet: '192.168.7.0/24', lanInterface: 'usb0' });
  const preflight = () => {
    verifyGuard(locks);
    assert.ok(!links(locks).some(l => l.ifname === 'tun0'), 'live/replaced TUN; automatic recovery refused');
    if (pending(host)) { assert.equal(host.state.tun, 'tun0'); host.audit(); }
    if (pending(ipv6)) {
      assert.equal(ipv6.state.config.role, 'client'); assert.equal(ipv6.state.config.tun, 'tun0'); ipv6.audit();
    }
    if (pending(dns)) {
      const c = dns.state.config;
      assert.equal(c.tun, 'tun0');
      assert.deepEqual({ fromTun: c.fromTun, lanSubnet: c.lanSubnet, lanInterface: c.lanInterface }, scope);
      dns.restore({ apply: false });
    }
  };
  // Audit ALL owners before the first write, and again between phases. Never
  // delete journals, relax the standalone guard, or touch USB/SSH/services.
  preflight();
  for (const journal of [dns, ipv6, host]) {
    if (!pending(journal)) continue;
    preflight(); journal.restore();
  }
  verifyGuard(locks);
  log('[clean-vpn] usb-recovery: stale DNS/IPv6/IPv4 ownership restored under strict guard');
  return true;
}
