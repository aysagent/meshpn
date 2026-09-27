/** Durable file rollback AFTER independently verified DNS disable. No service
 * stop/reload or runtime-journal deletion. Like the file publisher, this core
 * takes a trusted OS observer; it is not itself live-install authority. */
import assert from 'node:assert/strict';
import { lstat, realpath, readdir } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { dnsDeployment, readDnsDeployment, validateDnsDeployment } from './dns-deployment.mjs';
import { readPrivateJournal, writePrivateJournal } from './dns-lifecycle-journal.mjs';
import { assertDnsCommandLock } from './dns-system-command.mjs';
import { validateDnsBootPolicy, DNS_BOOT_POLICY } from './dns-boot-guard.mjs';

const hash = (v) => createHash('sha256').update(v).digest('hex');
const keys = (v, names) => {
  assert.ok(v && typeof v === 'object' && !Array.isArray(v));
  assert.deepEqual(Object.keys(v).sort(), [...names].sort());
};
export function dnsDeploymentRemovalBinding(deployment) {
  validateDnsDeployment(deployment);
  // All ownership/plan fields are immutable; only the publisher's stage changes.
  const { stage, ...binding } = deployment;
  return hash(JSON.stringify(binding));
}
export function validateDnsRemovalPolicy(text, deployment) {
  assert.equal(typeof text, 'string'); assert.ok(Buffer.byteLength(text) > 0 && Buffer.byteLength(text) <= 2048);
  const policy = validateDnsBootPolicy(JSON.parse(text)); assert.equal(policy.input.client, 'vps2');
  validateDnsDeployment(deployment);
  assert.equal(hash(text), deployment.files.find((f) => f.path === DNS_BOOT_POLICY)?.sha256, 'guard policy is not the installed deployment policy');
  return policy;
}
export function validateDnsReleasedRemoval(record) {
  keys(record, ['schema', 'backend', 'id', 'root', 'rootIdentity', 'directoryIdentity', 'deploymentDirectory',
    'deploymentBinding', 'policyText', 'historySha256', 'stage']);
  assert.equal(record.schema, 1); assert.equal(record.backend, 'dns-released-removal'); assert.match(record.id, /^[a-f0-9]{32}$/);
  for (const p of [record.root, record.deploymentDirectory]) assert.equal(resolve(p), p);
  for (const id of [record.rootIdentity, record.directoryIdentity]) assert.match(id, /^\d+:\d+:\d+$/);
  for (const h of [record.deploymentBinding, record.historySha256]) assert.match(h, /^[a-f0-9]{64}$/);
  assert.equal(typeof record.policyText, 'string'); assert.ok(Buffer.byteLength(record.policyText) <= 2048);
  assert.equal(validateDnsBootPolicy(JSON.parse(record.policyText)).input.client, 'vps2');
  assert.ok(['removing', 'removed'].includes(record.stage)); return record;
}
export const readDnsReleasedRemoval = (directory) => readPrivateJournal(directory, validateDnsReleasedRemoval, 8192);
const identity = async (path, privateMode = false) => {
  const s = await lstat(path, { bigint: true });
  assert.ok(s.isDirectory() && s.uid === BigInt(process.getuid()) && !(s.mode & 0o022n));
  if (privateMode) assert.equal(s.mode & 0o7777n, 0o700n);
  return `${s.dev}:${s.ino}:${s.mode}`;
};
export function validateDnsReleasedObservation(report) {
  assert.equal(report?.schema, 1); assert.equal(report.kind, 'clean-vpn-dns-released-deployment-check');
  assert.equal(report.releasedInactive, true); assert.equal(report.systemSettingsChanged, false);
  assert.equal(report.dnsQueriesSent, 0); assert.equal(report.activationAuthorized, false);
  assert.equal(report.uninstallAuthorized, false); assert.match(report.historySha256, /^[a-f0-9]{64}$/);
  return report.historySha256;
}

export async function removeReleasedDnsDeployment({ root, directory, deploymentDirectory, operation,
  policyText, lockFd, inspectReleased, checkpoint = async () => {} }) {
  assert.ok(['remove', 'recover', 'inspect'].includes(operation)); assert.equal(typeof inspectReleased, 'function');
  for (const path of [root, directory, deploymentDirectory]) {
    assert.equal(resolve(path), path); assert.equal(await realpath(path), path);
  }
  const target = join(root, 'opt/clean-vpn'), runtime = join(root, 'var/lib/clean-vpn/dns-v1');
  const disjoint = (a, b) => assert.ok(a !== b && !a.startsWith(`${b}/`) && !b.startsWith(`${a}/`), 'overlapping removal/deployment/runtime paths');
  disjoint(directory, deploymentDirectory);
  for (const path of [directory, deploymentDirectory]) { disjoint(path, target); disjoint(path, runtime); }
  const rootIdentity = await identity(root), directoryIdentity = await identity(directory, true);
  let record;
  try { record = await readDnsReleasedRemoval(directory); }
  catch (e) { if (e.code !== 'ENOENT' || operation !== 'remove') throw e; }
  let persisted = record ? structuredClone(record) : null;
  const deployment = await readDnsDeployment(deploymentDirectory), binding = dnsDeploymentRemovalBinding(deployment);
  if (record) {
    assert.equal(record.root, root); assert.equal(record.rootIdentity, rootIdentity); assert.equal(record.directoryIdentity, directoryIdentity);
    assert.equal(record.deploymentDirectory, deploymentDirectory); assert.equal(record.deploymentBinding, binding);
    if (policyText !== undefined) assert.equal(policyText, record.policyText, 'removal policy changed');
    policyText = record.policyText;
  } else {
    assert.deepEqual(await readdir(directory), [], 'unjournalled removal state requires review');
    assert.equal(deployment.stage, 'installed', 'released removal requires a complete installed deployment');
  }
  const policy = validateDnsRemovalPolicy(policyText, deployment);
  let historySha256 = record?.historySha256;
  const context = async () => {
    await assertDnsCommandLock(lockFd);
    assert.equal(await realpath(root), root); assert.equal(await realpath(directory), directory);
    assert.equal(await realpath(deploymentDirectory), deploymentDirectory);
    assert.equal(await identity(root), rootIdentity); assert.equal(await identity(directory, true), directoryIdentity);
    if (persisted) assert.deepEqual(await readDnsReleasedRemoval(directory), persisted, 'removal journal changed');
    else await assert.rejects(lstat(join(directory, 'journal.json')), { code: 'ENOENT' });
    const current = await readDnsDeployment(deploymentDirectory);
    assert.equal(dnsDeploymentRemovalBinding(current), binding, 'deployment binding changed');
    assert.ok(['installed', 'removing-files', 'removing-code', 'removed'].includes(current.stage));
    if (record?.stage === 'removed') assert.equal(current.stage, 'removed');
    return current;
  };
  const inactive = async () => {
    await context();
    const observed = validateDnsReleasedObservation(await inspectReleased(structuredClone(policy)));
    if (historySha256 === undefined) historySha256 = observed;
    else assert.equal(observed, historySha256, 'released runtime history changed during removal');
    await context(); return true;
  };
  const run = (op) => dnsDeployment({ root, directory: deploymentDirectory, operation: op, lockFd,
    assertInactive: inactive, checkpoint: (point) => checkpoint(`deployment:${point}`) });
  await inactive();
  await run('inspect'); // Verify both file/code inventories before durable intent.
  const save = async (stage) => {
    await inactive(); record = { ...record, stage };
    await writePrivateJournal(directory, record, validateDnsReleasedRemoval, checkpoint, 8192, stage);
    persisted = structuredClone(record);
  };
  if (!record) {
    record = { schema: 1, backend: 'dns-released-removal', id: randomBytes(16).toString('hex'), root, rootIdentity,
      directoryIdentity, deploymentDirectory, deploymentBinding: binding, policyText, historySha256, stage: 'removing' };
    await save('removing');
  }
  if (operation !== 'inspect' && record.stage === 'removing') {
    assert.equal((await run('remove')).stage, 'removed'); await save('removed');
  }
  await inactive();
  return { schema: 1, kind: 'clean-vpn-dns-released-removal', id: record.id, stage: record.stage,
    runtimeHistoryRetained: true, servicesStoppedByThisOperation: false, codeRetainedInArchive: record.stage === 'removed' };
}
