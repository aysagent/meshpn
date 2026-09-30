import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
const file = new URL('./autostart/killswitch.sh', import.meta.url).pathname;
const plan = (...args) => spawnSync('/bin/bash', [file, 'plan', ...args], {
  encoding: 'utf8', timeout: 3000, env: { PATH: '/no-tools', BASH_ENV: '/dev/null' },
});
test('read-only plans need no network commands; allow rules never ACCEPT or allow all ESTABLISHED', () => {
  const r = plan('--server=198.51.100.2'); assert.equal(r.status, 0, r.stderr);
  assert.equal((r.stdout.match(/^COMMIT$/gm) || []).length, 2);
  assert.doesNotMatch(r.stdout, /-j ACCEPT|-F |--ctstate ESTABLISHED -j/);
  for (const line of r.stdout.split('\n').filter(l => l.includes('--ctstate'))) {
    assert.match(line, /--sport 22 .*--ctstate ESTABLISHED --ctdir REPLY -j RETURN$/);
  }
  assert.match(r.stdout, /-o tun0 -j RETURN/); assert.match(r.stdout, /-d ff02::\/16/);
});
for (const arg of ['--server=evil.test', '--server=1.2.3.999', '--server=127.0.0.1',
  '--server=224.1.2.3', '--server=01.2.3.4', '--server=1.2.3.4,', '--server=1.2.3.4,,2.3.4.5',
  '--server=1.2.3.4\nCOMMIT', '--tun=lo', '--tun=tun+', '--scope=all',
  '--ipv6=off', '--ssh-port=65536', '--ssh-port=-1']) {
  test(`invalid guard option fails before any plan: ${JSON.stringify(arg)}`, () => {
    const r = plan(...(arg.startsWith('--server=') ? [arg] : ['--server=198.51.100.2', arg]));
    assert.notEqual(r.status, 0); assert.equal(r.stdout, '');
  });
}
test('duplicate options refused; explicit forward-only/leave and custom SSH are represented', () => {
  assert.notEqual(plan('--server=1.2.3.4', '--server=2.3.4.5').status, 0);
  const r = plan('--server=198.51.100.2', '--scope=fwd', '--ipv6=leave');
  assert.equal(r.status, 0, r.stderr); assert.doesNotMatch(r.stdout, /OUTPUT|CLEANVPN_KS_OUT|ip6/);
  assert.equal((r.stdout.match(/^COMMIT$/gm) || []).length, 1);
  assert.match(plan('--server=198.51.100.2', '--ssh-port=2222').stdout, /--sport 2222/);
  assert.doesNotMatch(plan('--server=198.51.100.2', '--ssh-port=0').stdout, /--ctstate/);
});
test('mutations use noflush test then commit, persistent flock, and no implicit down', () => {
  const s = readFileSync(file, 'utf8');
  assert.match(s, /flock -w 10 9/); assert.match(s, /--noflush --test/);
  assert.doesNotMatch(s.replace(/^\s*#.*$/gm, ''), /\beval\b|\bsource\b|\n\s*down\b|iptables -F/);
});
test('oversized ownership marker is rejected before output', () => {
  const r = plan(`--server=${Array(16).fill('198.151.100.222').join(',')}`, '--tun=abcdefghijklmno');
  assert.notEqual(r.status, 0); assert.equal(r.stdout, '');
});
