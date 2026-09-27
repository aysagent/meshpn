/** Fixed-layout bridge; no host CLI, implicit service stop/reload, directory
 * preparation or boot-epoch adoption. Integration remains separately gated. */
import assert from 'node:assert/strict';
import { lstat } from 'node:fs/promises';
import { assertDnsSystemCommands } from './dns-system-command.mjs';
import { requireDnsBootGuardLock, DNS_BOOT_POLICY } from './dns-boot-guard.mjs';
import { readTrustedDnsText } from './dns-installed-vps2.mjs';
import { inspectReleasedDnsDeployment } from './dns-deployment-inactive.mjs';
import { readDnsReleasedRemoval, removeReleasedDnsDeployment } from './dns-released-removal.mjs';

export const DNS_DEPLOYMENT_DIRECTORY = '/var/lib/clean-vpn/deployment';
export const DNS_REMOVAL_DIRECTORY = '/var/lib/clean-vpn/removal';
export async function removeInstalledReleasedDnsDeployment({ commands, operation, checkpoint }) {
  assertDnsSystemCommands(commands); assert.ok(['remove', 'recover', 'inspect'].includes(operation));
  assert.equal(process.platform, 'linux'); assert.equal(process.getuid(), 0);
  const parents = async () => {
    for (const p of ['/', '/var', '/var/lib', '/var/lib/clean-vpn']) {
      const s = await lstat(p); assert.ok(s.isDirectory() && s.uid === 0 && !(s.mode & 0o022));
    }
  };
  await parents(); const lockFd = await requireDnsBootGuardLock();
  let policyText;
  try { await readDnsReleasedRemoval(DNS_REMOVAL_DIRECTORY); }
  catch (e) {
    if (e.code !== 'ENOENT' || operation !== 'remove') throw e;
    policyText = (await readTrustedDnsText(DNS_BOOT_POLICY, 0o600, undefined, 2048)).text;
  }
  return removeReleasedDnsDeployment({ root: '/', directory: DNS_REMOVAL_DIRECTORY,
    deploymentDirectory: DNS_DEPLOYMENT_DIRECTORY, operation, policyText, lockFd, checkpoint,
    inspectReleased: async (policy) => {
      await parents(); assert.equal(await requireDnsBootGuardLock(), lockFd);
      return inspectReleasedDnsDeployment({ commands, input: policy.input, firewallBackend: policy.firewallBackend });
    } });
}
