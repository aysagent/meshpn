/** Destructive fault injection is confined to disposable user/net/mount/PID namespaces. */
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import { assertBrowserNamespace } from './browser-soak.mjs';
import { inspectIngress, installIngressRouting } from './ingress-routing.mjs';
import { openIngressJournal } from './ingress-journal.mjs';

const run = (f, a) => execFileSync(f, a, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const ip = (...a) => run('ip', a);
const directory = '/run/ingress-recovery-test';
const snapshot = () => JSON.stringify([
  run('iptables', ['-S']), run('iptables', ['-t', 'nat', '-S']), run('ip6tables', ['-S']),
  ip('-j', '-4', 'route', 'show', 'table', 'all'), ip('-j', '-4', 'rule', 'show'),
  run('sysctl', ['-n', 'net/ipv4/conf/wg0/rp_filter']),
]);

export function runIngressRecoveryLab() {
  assertBrowserNamespace();
  assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map((l) => l.ifname), ['lo']);
  run('mount', ['--make-rprivate', '/']); run('mount', ['-t', 'tmpfs', 'tmpfs', '/run']);
  ip('link', 'set', 'lo', 'up'); run('sysctl', ['-w', 'net.ipv4.ip_forward=1']);
  for (const [name, peer, address] of [['wg0', 'peer0', '10.44.0.1/24'], ['cvpntun', 'tunpeer', '10.99.0.2/24']]) {
    ip('link', 'add', name, 'type', 'veth', 'peer', 'name', peer); ip('link', 'set', name, 'up'); ip('link', 'set', peer, 'up');
    ip('addr', 'add', address, 'dev', name);
  }
  run('sysctl', ['-w', 'net/ipv4/conf/wg0/rp_filter=1']);
  const config = { ingress: inspectIngress('wg0'), tun: 'cvpntun', address: '10.99.0.2' };
  const before = snapshot(), checks = [];
  const open = (options) => openIngressJournal(directory, options);
  const start = (journal) => {
    const transaction = journal.begin(config);
    const owner = installIngressRouting({ ...config, tag: transaction.tag }, { transaction });
    owner.installHttpsRedirect(19443); return owner;
  };
  const recover = () => { const j = open(); try { return j.restore(); } finally { j.release(); } };
  let journal = open(); const owner = start(journal);
  assert.throws(() => open(), /locked/); checks.push('flock refuses second live owner');
  assert.throws(() => openIngressJournal('/run/different-state-directory'), /locked/);
  checks.push('alternative journal directory cannot bypass namespace lock');
  owner.close(); assert.equal(snapshot(), before); checks.push('normal stop restores exact baseline');
  const childSource = `
    import {openIngressJournal} from './scripts/lib/ingress-journal.mjs';
    import {installIngressRouting} from './scripts/lib/ingress-routing.mjs';
    const config=${JSON.stringify(config)};
    const journal=openIngressJournal(${JSON.stringify(directory)}, {checkpoint(label,v) {
      if (label === process.env.CUT_LABEL && v.stage === process.env.CUT_STAGE && v.count === Number(process.env.CUT_COUNT)) process.kill(process.pid,'SIGKILL');
    }});
    if (process.env.RESTORE === '1') journal.restore();
    else {
      const transaction=journal.begin(config);
      const owner=installIngressRouting({...config,tag:transaction.tag},{transaction});
      owner.installHttpsRedirect(19443);
      process.kill(process.pid,'SIGKILL');
    }
  `;
  const crash = (env = {}) => {
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', childSource], {
      encoding: 'utf8', timeout: 15000, env: { ...process.env, ...env },
    });
    assert.equal(r.signal, 'SIGKILL', r.stderr);
  };
  crash();
  const total = JSON.parse(fs.readFileSync(`${directory}/journal.json`)).count;
  journal = open(); const current = snapshot();
  assert.equal(journal.restore({ apply: false }).mode, 'dry-run'); assert.equal(snapshot(), current);
  assert.throws(() => journal.restore({ name: 'other0' }), /name does not match/); journal.release();
  checks.push('dry-run/wrong interface do not mutate network');
  recover(); assert.equal(snapshot(), before); assert.equal(recover().operations, 0);
  checks.push('SIGKILL recovery and repeat recovery restore baseline');
  // Intent before mutation; kernel mutation before ack; cleanup before cursor update; atomic journal replacement.
  for (const label of ['file-synced', 'renamed', 'dir-synced', 'applied']) {
    for (const count of [1, 14, 20, 30, total]) {
      crash({ CUT_LABEL: label, CUT_STAGE: 'installing', CUT_COUNT: String(count) });
      recover(); assert.equal(snapshot(), before, `${label}/${count}`);
    }
  }
  checks.push('20 installation/journal crash points restore baseline');
  for (const label of ['removed', 'file-synced', 'renamed', 'dir-synced']) {
    crash(); crash({ RESTORE: '1', CUT_LABEL: label, CUT_STAGE: 'restoring', CUT_COUNT: '20' });
    recover(); assert.equal(snapshot(), before);
  }
  checks.push('interrupted recovery is resumable at four journal boundaries');
  crash();
  run('iptables', ['-A', 'CVPN-INGRESS', '-p', 'udp', '--dport', '123', '-j', 'DROP']);
  const foreign = snapshot(); assert.throws(recover, /foreign/); assert.equal(snapshot(), foreign);
  run('iptables', ['-D', 'CVPN-INGRESS', '-p', 'udp', '--dport', '123', '-j', 'DROP']);
  run('sysctl', ['-w', 'net/ipv4/conf/wg0/rp_filter=0']);
  const changed = snapshot(); assert.throws(recover, /rp_filter conflict/); assert.equal(snapshot(), changed);
  run('sysctl', ['-w', 'net/ipv4/conf/wg0/rp_filter=2']);
  recover(); assert.equal(snapshot(), before); checks.push('foreign firewall/sysctl changes cause non-mutating refusal');
  // Unrelated administrator rules survive cleanup.
  crash(); run('iptables', ['-A', 'INPUT', '-p', 'udp', '--dport', '123', '-j', 'DROP']); recover();
  assert.match(run('iptables', ['-S', 'INPUT']), /--dport 123/);
  run('iptables', ['-D', 'INPUT', '-p', 'udp', '--dport', '123', '-j', 'DROP']);
  assert.equal(snapshot(), before); checks.push('unrelated administrator rules preserved');
  crash(); ip('link', 'del', 'cvpntun');
  ip('link', 'add', 'cvpntun', 'type', 'veth', 'peer', 'name', 'newpeer');
  const replaced = snapshot(); assert.throws(recover, /identity changed/); assert.equal(snapshot(), replaced);
  ip('link', 'del', 'cvpntun'); recover();
  assert.doesNotMatch(run('iptables', ['-S']), /CVPN-INGRESS/);
  assert.equal(run('sysctl', ['-n', 'net/ipv4/conf/wg0/rp_filter']), '1');
  checks.push('replacement interface refused; vanished TUN handled');
  const path = `${directory}/journal.json`, saved = fs.readFileSync(path);
  const bad = JSON.parse(saved); bad.scope.boot = '00000000-0000-0000-0000-000000000000';
  fs.writeFileSync(path, JSON.stringify(bad)); assert.throws(recover, /different boot/);
  fs.writeFileSync(path, '{broken'); assert.throws(() => open());
  fs.writeFileSync(path, saved); fs.chmodSync(path, 0o644); assert.throws(() => open(), /unsafe/);
  checks.push('old-boot/corrupt/insecure journal refused');
  return { status: 'passed', checks, faultPoints: 24, hostNetworkChanged: false };
}
