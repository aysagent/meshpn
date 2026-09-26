/** Private child controller. Parent PID1 owns the namespace-only backend RPC. */
import assert from 'node:assert/strict';
import { readlink } from 'node:fs/promises';
import { createInterface } from 'node:readline';
import { dnsTransaction } from './dns-lifecycle-transaction.mjs';
import { resolvedTransaction } from './dns-resolved-journal.mjs';
import { dnsmasqTransaction } from './dnsmasq-journal.mjs';
import { ownedLinkTransaction } from './dns-owned-link-journal.mjs';
import { coupledDnsTransaction } from './dns-coupled-journal.mjs';

let input, timer;
try {
  assert.equal(process.ppid, 1, 'namespace init must own controller');
  assert.notEqual(process.pid, 1);
  assert.equal(await readlink('/proc/self'), String(process.pid), 'private proc required');
  const scope = {};
  for (const key of ['net', 'mnt', 'pid']) {
    scope[key] = await readlink(`/proc/self/ns/${key}`);
    assert.equal(scope[key], await readlink(`/proc/1/ns/${key}`));
    const host = process.env[`MESHPN_PARENT_${key === 'mnt' ? 'MNT' : key === 'net' ? 'NET' : 'PID'}NS`];
    assert.ok(host); assert.notEqual(scope[key], host, 'host namespace forbidden');
  }
  assert.equal(process.env.MESHPN_DNS_CONTROLLER, 'namespace-rpc');
  input = createInterface({ input: process.stdin });
  let sequence = 0, pending;
  const call = (type, payload) => new Promise((resolve, reject) => {
    assert.equal(pending, undefined);
    const id = ++sequence;
    timer = setTimeout(() => { pending = undefined; reject(new Error('RPC timeout')); }, 10000);
    pending = { id, resolve, reject };
    process.stdout.write(`${JSON.stringify({ id, type, ...payload })}\n`);
  });
  input.on('line', (line) => {
    try {
      assert.ok(line.length < 16384); const reply = JSON.parse(line);
      assert.equal(reply.id, pending?.id); clearTimeout(timer);
      const request = pending; pending = undefined;
      if (reply.error) request.reject(new Error('fixture backend refused operation')); else request.resolve(reply.value);
    } catch { process.exit(2); }
  });
  input.once('close', () => { if (pending) { clearTimeout(timer); pending.reject(new Error('backend disconnected')); pending = undefined; } });
  const kind = process.argv[4] ?? 'file'; assert.ok(['file', 'resolved', 'dnsmasq', 'link', 'coupled'].includes(kind));
  const methods = kind === 'coupled' ? ['ensureGuard', 'context', 'view', 'linkView', 'create', 'stamp', 'remove', 'releaseGuard', 'adapterPort', 'probe', 'set']
    : kind === 'link' ? ['ensureGuard', 'context', 'view', 'create', 'stamp', 'remove', 'releaseGuard']
    : kind === 'resolved' ? ['ensureGuard', 'view', 'set', 'removeGuard', 'probe', 'adapterPort']
    : kind === 'dnsmasq' ? ['ensureGuard', 'view', 'prepare', 'verifySnapshots', 'select', 'activate', 'removeGuard', 'probe']
    : ['ensureGuard', 'prepare', 'current', 'verifySnapshots', 'select', 'removeGuard', 'probe'];
  const backend = Object.fromEntries(methods
    .map((method) => [method, (...args) => call('backend', { method, args })]));
  const transaction = kind === 'coupled' ? coupledDnsTransaction : kind === 'link' ? ownedLinkTransaction : kind === 'dnsmasq' ? dnsmasqTransaction : kind === 'resolved' ? resolvedTransaction : dnsTransaction;
  const result = await transaction({ directory: process.argv[2], operation: process.argv[3], scope, backend,
    checkpoint: (point) => call('checkpoint', { point }) });
  process.stdout.write(`${JSON.stringify({ type: 'result', result })}\n`);
} catch { process.stderr.write('DNS_CONTROLLER_REFUSED\n'); process.exitCode = 2; }
finally { clearTimeout(timer); input?.close(); process.stdin.destroy(); }
