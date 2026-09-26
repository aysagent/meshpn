import assert from 'node:assert/strict';
import test from 'node:test';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';
import { assertNetworkdEvidence } from './lib/dns-networkd-lab.mjs';

test('resolved 249 + networkd: real DHCP renewal/reconfigure, owned VPN link and current-baseline disable', { timeout: 135000 }, async () => {
  assert.ok(process.env.MESHPN_SYSTEMD249_DIR?.startsWith('/'), 'absolute MESHPN_SYSTEMD249_DIR required');
  assert.ok(process.env.MESHPN_DNSMASQ?.startsWith('/'), 'absolute MESHPN_DNSMASQ required');
  const r = await runCommand(process.execPath, ['scripts/dns-networkd-lab.mjs',
    `--systemd-dir=${process.env.MESHPN_SYSTEMD249_DIR}`, `--dnsmasq=${process.env.MESHPN_DNSMASQ}`],
  { env: cleanEnvironment(process.env), timeoutMs: 130000, maxBytes: 128 * 1024 });
  assert.equal(r.reason, null); assert.equal(r.code, 0, r.stderr);
  const report = JSON.parse(r.stdout); assertNetworkdEvidence(report);
  assert.equal(report.separateCloudNamespace, true); assert.ok(report.dhcp.acks >= 3);
  assert.match(report.versions['systemd-resolved'], /^systemd 249 /);
});
