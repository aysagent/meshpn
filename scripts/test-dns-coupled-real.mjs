import test from 'node:test';
import assert from 'node:assert/strict';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';
import { assertNetworkdEvidence } from './lib/dns-networkd-lab.mjs';

test('coupled networkd namespace journal: DNS/link SIGKILL, fail-closed and current DHCP disable', { timeout: 255000 }, async () => {
  assert.ok(process.env.MESHPN_SYSTEMD249_DIR?.startsWith('/'));
  assert.ok(process.env.MESHPN_DNSMASQ?.startsWith('/'));
  const r = await runCommand(process.execPath, ['scripts/dns-networkd-lab.mjs', '--coupled-journal',
    `--systemd-dir=${process.env.MESHPN_SYSTEMD249_DIR}`, `--dnsmasq=${process.env.MESHPN_DNSMASQ}`],
  { env: cleanEnvironment(process.env), timeoutMs: 250000, maxBytes: 128 * 1024 });
  assert.equal(r.reason, null); assert.equal(r.code, 0, r.stderr);
  assertNetworkdEvidence(JSON.parse(r.stdout), { coupledJournal: true });
});
