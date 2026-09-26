import assert from 'node:assert/strict';
import test from 'node:test';
import { runCommand, cleanEnvironment } from './lib/transparent-acceptance.mjs';
import { assertNetworkdEvidence } from './lib/dns-networkd-lab.mjs';

test('networkd private lab: durable empty-link creation/deletion and controller SIGKILL', { timeout: 135000 }, async () => {
  assert.ok(process.env.MESHPN_SYSTEMD249_DIR?.startsWith('/'), 'absolute MESHPN_SYSTEMD249_DIR required');
  assert.ok(process.env.MESHPN_DNSMASQ?.startsWith('/'), 'absolute MESHPN_DNSMASQ required');
  const r = await runCommand(process.execPath, ['scripts/dns-networkd-lab.mjs', '--link-journal',
    `--systemd-dir=${process.env.MESHPN_SYSTEMD249_DIR}`, `--dnsmasq=${process.env.MESHPN_DNSMASQ}`],
  { env: cleanEnvironment(process.env), timeoutMs: 130000, maxBytes: 128 * 1024 });
  assert.equal(r.reason, null); assert.equal(r.code, 0, r.stderr);
  assertNetworkdEvidence(JSON.parse(r.stdout), { linkJournal: true });
});
