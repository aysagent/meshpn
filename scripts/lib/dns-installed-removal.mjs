/** Fixed-layout post-disable uninstall bridge. No host CLI, directory
 * preparation or boot-epoch adoption. New intents detach owned dependencies
 * before daemon-reload/guard stop; legacy intents retain their strict gate. */
import assert from 'node:assert/strict';
import { lstat } from 'node:fs/promises';
import { assertDnsSystemCommands } from './dns-system-command.mjs';
import { requireDnsBootGuardLock, DNS_BOOT_POLICY } from './dns-boot-guard.mjs';
import { readTrustedDnsText } from './dns-installed-vps2.mjs';
import { inspectReleasedDnsDeployment, inspectQuiescentDnsDeployment } from './dns-deployment-inactive.mjs';
import { readDnsReleasedRemoval, removeReleasedDnsDeployment } from './dns-released-removal.mjs';

export const DNS_DEPLOYMENT_DIRECTORY = '/var/lib/clean-vpn/deployment';
export const DNS_REMOVAL_DIRECTORY = '/var/lib/clean-vpn/removal';
export function assertDnsGuardStopDependencies(text) {
  const fields = ['RequiredBy', 'BoundBy', 'ConsistsOf', 'PropagatesStopTo', 'OnSuccess', 'OnFailure'];
  const allowed = new Set(['clean-vpn-dns-client.service', 'clean-vpn-dns-adapter.service', 'clean-vpn-dns-disable.service']);
  assert.equal(typeof text, 'string'); assert.ok(Buffer.byteLength(text) <= 16384);
  const seen = new Set();
  for (const line of text.trimEnd().split('\n')) {
    const at = line.indexOf('='), name = line.slice(0, at), value = line.slice(at + 1);
    assert.ok(at > 0 && fields.includes(name) && !seen.has(name)); seen.add(name);
    const targets = value ? value.split(' ') : [];
    assert.ok(targets.every((v) => allowed.has(v)) && new Set(targets).size === targets.length, 'unreviewed guard stop dependency');
    if (['PropagatesStopTo', 'OnSuccess', 'OnFailure'].includes(name)) assert.equal(targets.length, 0);
  }
  assert.equal(seen.size, fields.length);
}
export async function removeInstalledReleasedDnsDeployment({ commands, operation, checkpoint }) {
  assertDnsSystemCommands(commands); assert.ok(['remove', 'recover', 'inspect'].includes(operation));
  assert.equal(process.platform, 'linux'); assert.equal(process.getuid(), 0);
  const parents = async () => {
    for (const p of ['/', '/var', '/var/lib', '/var/lib/clean-vpn']) {
      const s = await lstat(p); assert.ok(s.isDirectory() && s.uid === 0 && !(s.mode & 0o022));
    }
  };
  await parents(); const lockFd = await requireDnsBootGuardLock();
  let policyText, record;
  try { record = await readDnsReleasedRemoval(DNS_REMOVAL_DIRECTORY); }
  catch (e) {
    if (e.code !== 'ENOENT' || operation !== 'remove') throw e;
    policyText = (await readTrustedDnsText(DNS_BOOT_POLICY, 0o600, undefined, 2048)).text;
  }
  const lifecycle = !record || record.schema === 2;
  const observe = async (policy, quiescent = false) => {
    await parents(); assert.equal(await requireDnsBootGuardLock(), lockFd);
    return (quiescent ? inspectQuiescentDnsDeployment : inspectReleasedDnsDeployment)({ commands,
      input: policy.input, firewallBackend: policy.firewallBackend, trackManagers: lifecycle });
  };
  return removeReleasedDnsDeployment({ root: '/', directory: DNS_REMOVAL_DIRECTORY,
    deploymentDirectory: DNS_DEPLOYMENT_DIRECTORY, operation, policyText, lockFd, checkpoint,
    inspectReleased: (policy) => observe(policy),
    ...(lifecycle ? {
      inspectQuiescent: (policy) => observe(policy, true),
      settleServices: async (policy, evidence) => {
        const verify = async () => {
          const report = await observe(policy, true);
          assert.equal(report.historySha256, evidence.historySha256);
          assert.equal(report.managersSha256, evidence.managersSha256);
          return report;
        };
        await verify();
        await commands.run('systemctl', ['daemon-reload'], { timeoutMs: 30000 });
        await evidence.checkpoint('reloaded');
        const current = await verify(); assert.equal(current.managerNeedsReload, false);
        if (current.guardUnitActiveExited) {
          assertDnsGuardStopDependencies((await commands.run('systemctl', ['show', '--all', 'clean-vpn-dns-guard.service',
            ...['RequiredBy', 'BoundBy', 'ConsistsOf', 'PropagatesStopTo', 'OnSuccess', 'OnFailure'].map((v) => `--property=${v}`)])).stdout);
          await commands.run('systemctl', ['stop', 'clean-vpn-dns-guard.service'], { timeoutMs: 30000 });
        }
        await evidence.checkpoint('guard-stopped');
        await verify();
      },
    } : {}) });
}
