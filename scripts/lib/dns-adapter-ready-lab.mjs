/** CLI readiness across the actual public-contract adapter, namespace-local aliases only. */
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { startAdapterSoakLab } from './dns-adapter-soak-lab.mjs';
import { child } from './browser-lab-driver.mjs';
import { cleanEnvironment, runCommand } from './transparent-acceptance.mjs';
import { namespaceResources, assertBrowserNamespace } from './browser-soak.mjs';

export async function runDnsAdapterReadyLab(directory, family) {
  assertBrowserNamespace();
  const lab = await startAdapterSoakLab({ family, modeTag: 'combo-tls', concurrency: 4, timeoutMs: 1000,
    domainPolicy: { schema: 1, denySuffixes: ['blocked.test'] } }, directory);
  let args;
  const env = cleanEnvironment(process.env);
  delete env.NOTIFY_SOCKET; delete env.INVOCATION_ID;
  const checks = [], processes = [];
  const start = (name = 'ready.test') => {
    const p = child(process.execPath, [...args, `--ready-name=${name}`], { env }); processes.push(p); return p;
  };
  const ready = async (p) => {
    const r = JSON.parse((await p.waitFor(/DNS_EXIT_ADAPTER (\{[^\n]+\})/, 10000))[1]);
    assert.deepEqual(r, { status: 'ready', address: '127.0.0.1', port: lab.stub.port, systemDnsChanged: false,
      domainPolicyEnabled: true, readinessQueries: 4, systemdNotified: false });
  };
  const failed = async (name) => {
    const r = await runCommand(process.execPath, [...args, `--ready-name=${name}`], { env, timeoutMs: 10000 });
    assert.equal(r.reason, null); assert.equal(r.code, 1); assert.ok(r.stderr.includes('DNS_EXIT_ADAPTER_INVALID'));
    assert.ok(!r.stdout.includes('DNS_EXIT_ADAPTER '), 'must not advertise listening or ready after failure');
  };
  try {
    args = ['scripts/dns-exit-adapter.mjs', ...await lab.prepareCliAdapter()];
    const before = lab.stats().resolverBodies, normal = start(); await ready(normal);
    assert.equal(lab.stats().resolverBodies - before, 4); await normal.stop(); assert.equal(normal.proc.exitCode, 0);
    checks.push('four-probes-before-ready-and-clean-stop');
    const deniedBefore = lab.stats().resolverBodies; await failed('blocked.test');
    assert.equal(lab.stats().resolverBodies, deniedBefore); checks.push('denied-readiness-name-refused-before-network');
    await lab.stopExit(); const downBefore = lab.stats().resolverBodies; await failed('ready.test');
    assert.equal(lab.stats().resolverBodies, downBefore); checks.push('exit-down-no-ready'); await lab.restartExit();
    lab.setMode('reset'); await failed('ready.test'); checks.push('resolver-reset-no-ready');
    lab.setMode('nxdomain'); await failed('ready.test'); checks.push('negative-answer-no-ready');
    lab.setMode('hold'); const heldBefore = lab.stats().resolverBodies, held = start();
    let heldOutput = '';
    held.proc.stdout.on('data', (bytes) => { heldOutput = (heldOutput + bytes.toString()).slice(-8192); });
    for (let i = 0; i < 200 && lab.stats().resolverBodies === heldBefore; i++) await delay(10);
    assert.ok(lab.stats().resolverBodies > heldBefore, 'readiness must be in flight before signal');
    await held.stop('SIGTERM'); assert.equal(held.proc.exitCode, 0); assert.equal(heldOutput.includes('DNS_EXIT_ADAPTER '), false);
    checks.push('sigterm-during-probe-no-ready');
    lab.setMode('normal'); const recovered = start(); await ready(recovered); await recovered.stop();
    assert.equal(recovered.proc.exitCode, 0); checks.push('port-reusable-and-recovery-ready');
    assert.equal(lab.stats().dnsCalls, 0);
  } finally {
    for (const p of processes) await p.stop(); await lab.close();
  }
  await delay(20); const resources = namespaceResources();
  assert.equal(resources.tree.live, 1); assert.equal(resources.tree.zombies, 0);
  for (const key of ['Timeout', 'TCPSocketWrap', 'TCPServerWrap', 'ProcessWrap', 'UDPWrap']) assert.equal(resources.worker.active[key] ?? 0, 0);
  return { status: 'passed', family, checks, dnsCalls: 0, systemDnsChanged: false, systemdNotificationTested: false,
    resources: { processes: resources.tree.live, zombies: resources.tree.zombies } };
}
