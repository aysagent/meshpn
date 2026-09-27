import assert from 'node:assert/strict';
import test from 'node:test';
import { parseDnsDeploymentUnits, assertNoDnsDeploymentJobs, assertNoDnsDeploymentProcesses,
  assertNoDnsDeploymentLinks, assertNoManualDnsDeploymentProcess, inspectFreshDnsDeployment } from './lib/dns-deployment-inactive.mjs';

const json = (type, data) => JSON.stringify({ type, data });
const unit = () => ['clean-vpn-dns-client.service', 'Client', 'loaded', 'inactive', 'dead', '',
  '/org/freedesktop/systemd1/unit/clean_2dvpn_2ddns_2dclient_2eservice', 0, '', '/'];
test('fresh inspection accepts only exact inactive service tuples, including no loaded units', () => {
  assert.deepEqual(parseDnsDeploymentUnits(json('a(ssssssouso)', [[]])), []);
  assert.equal(parseDnsDeploymentUnits(json('a(ssssssouso)', [[unit()]]))[0].name, unit()[0]);
  const v = unit(); v[2] = 'not-found'; assert.equal(parseDnsDeploymentUnits(json('a(ssssssouso)', [[v]])).length, 1);
});
for (const [field, value] of [[0, 'clean-vpn-dns-foreign.timer'], [2, 'masked'], [3, 'active'], [3, 'failed'],
  [3, 'activating'], [3, 'deactivating'], [4, 'running'], [5, 'alias.service'], [7, 1], [7, '0'], [8, 'start'], [6, '/wrong/path']])
  test(`service activity/shape ${field}:${value} cannot authorize file changes`, () => {
    const row = unit(); row[field] = value; assert.throws(() => parseDnsDeploymentUnits(json('a(ssssssouso)', [[row]])));
  });
test('duplicate, malformed, oversized and untyped unit replies fail closed', () => {
  for (const text of [json('s', [[]]), json('a(ssssssouso)', []), json('a(ssssssouso)', [[unit(), unit()]]),
    json('a(ssssssouso)', [[unit().slice(1)]]), 'x'.repeat(262145), '{}']) assert.throws(() => parseDnsDeploymentUnits(text));
});
test('jobs for DNS, DNS timers and either manager prevent fresh mutation; unrelated jobs are permitted', () => {
  assertNoDnsDeploymentJobs(json('a(usssoo)', [[]]));
  const row = [2, 'unrelated.service', 'start', 'waiting', '/unit', '/job'];
  assertNoDnsDeploymentJobs(json('a(usssoo)', [[row]]));
  for (const name of ['clean-vpn-dns-client.service', 'clean-vpn-dns-other.timer', 'systemd-resolved.service', 'systemd-networkd.service'])
    assert.throws(() => assertNoDnsDeploymentJobs(json('a(usssoo)', [[[...row][0], name, ...row.slice(2)]])));
  assert.throws(() => assertNoDnsDeploymentJobs(json('a(usssoo)', [[row.slice(1)]])));
});
test('zero MainPID alone is not proof: ControlPID and all cgroup processes must also be absent', () => {
  const pids = `${json('u', 0)}\n${json('u', 0)}\n`;
  assertNoDnsDeploymentProcesses(pids, json('a(sus)', [[]]));
  for (const text of [json('u', 0), `${json('u', 0)}\n${json('u', 42)}`, `${json('u', '0')}\n${json('u', 0)}`])
    assert.throws(() => assertNoDnsDeploymentProcesses(text, json('a(sus)', [[]])));
  assert.throws(() => assertNoDnsDeploymentProcesses(pids, json('a(sus)', [[['/group', 42, 'private args']]])),
    (e) => !e.stack.includes('private args') && !JSON.stringify(e).includes('private args'));
  assert.throws(() => assertNoDnsDeploymentProcesses(pids, json('a(sus)', [{}])));
});
test('leftover owned links or reserved address prevent fresh installation', () => {
  const rows = [{ ifname: 'lo', ifindex: 1, addr_info: [{ local: '127.0.0.1' }] }];
  assertNoDnsDeploymentLinks(JSON.stringify(rows));
  for (const mutate of [(v) => { v[0].ifname = 'cvdnsbad'; }, (v) => { v[0].addr_info[0].local = '192.0.2.1'; },
    (v) => { v.push(v[0]); }, (v) => { v[0].ifindex = '1'; }]) {
    const v = structuredClone(rows); mutate(v); assert.throws(() => assertNoDnsDeploymentLinks(JSON.stringify(v)));
  }
});
test('manual installed entrypoints are refused without logging arbitrary process argv', () => {
  assertNoManualDnsDeploymentProcess(Buffer.alloc(0));
  assertNoManualDnsDeploymentProcess(Buffer.from('/usr/bin/node\0some-script.mjs\0'));
  assertNoManualDnsDeploymentProcess(Buffer.from('node\0--eval\0a comment mentioning /opt/clean-vpn/scripts/dns-client.mjs\0'));
  for (const name of ['dns-client.mjs', 'dns-exit-adapter.mjs', 'dns-boot-guard.mjs'])
    assert.throws(() => assertNoManualDnsDeploymentProcess(Buffer.from(`node\0/opt/clean-vpn/scripts/${name}\0PRIVATE\0`)),
      (e) => !e.message.includes('PRIVATE'));
  assert.throws(() => assertNoManualDnsDeploymentProcess(Buffer.alloc(65537)));
});
test('caller cannot substitute a fake command runner for fresh deployment inspection', async () => {
  let called = false;
  await assert.rejects(inspectFreshDnsDeployment({ commands: { run: () => { called = true; } } }), /checked DNS system commands/);
  assert.equal(called, false);
});
