import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
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
test('rule plans remain byte-identical to published 4615121 guard', () => {
  // Hashes independently captured from the old script's read-only plan action.
  for (const [args, expected] of [
    [['--server=198.51.100.2'], '467996368e90c33f7f2a40caf036c2b05923dee7e9c2d818430001dd3a9707fb'],
    [['--server=198.51.100.2,203.0.113.2', '--scope=fwd', '--ipv6=leave'], '52a40e636e119635d0f2e948e43c99cae747d504b0b975c1b5c49f5daf4685f9'],
    [['--server=198.51.100.2', '--tun=tun9', '--ssh-port=0'], 'd2fc8049a6c3298067b852b920a11a6b4a73b8535b659ecf60e32bcc32efddab'],
    [['--server=198.51.100.2', '--ssh-port=2222'], '94244dad89d252db38759403d97544973dc1b1c0921b6783588922b5bfc41a13'],
  ]) {
    const r = plan(...args); assert.equal(r.status, 0, r.stderr);
    assert.equal(createHash('sha256').update(r.stdout).digest('hex'), expected);
  }
});

// Canonical nf_tables -S layout from the Radxa report (addresses/tags anonymized).
const dnsTag = 'clean-vpn-dns-tunnel-' + 'a'.repeat(24);
const v6Tag = 'clean-vpn-ipv6-' + 'b'.repeat(24), v6Chain = 'CV6_' + 'b'.repeat(16);
function activeSnapshot(family) {
  const block = plan('--server=198.51.100.2').stdout.split('*filter\n')[family === 4 ? 1 : 2];
  const lines = block.trim().split('\n');
  const declarations = lines.filter(l => l.startsWith(':')).map(l => '-N ' + l.split(' ')[0].slice(1));
  const hooks = lines.filter(l => l.startsWith('-I')).map(l => l.replace(/^-I (\S+) 1 /, '-A $1 '));
  const rules = lines.filter(l => l.startsWith('-A')).map(l => l.includes('--comment cvks2:') ? l.replace(/--comment (.+)$/, '--comment "$1"') : l);
  const prefix = [], chains = [];
  if (family === 4) {
    declarations.push('-N CVPN-DNS-OUT', '-N CVPN-DNS-IN');
    for (const p of ['tcp', 'udp']) prefix.push(
      `-A OUTPUT -d 10.99.0.2/32 -p ${p} -m comment --comment ${dnsTag} -m addrtype ! --dst-type LOCAL -m ${p} --dport 1053 -j REJECT --reject-with icmp-port-unreachable`,
      `-A OUTPUT -p ${p} -m comment --comment ${dnsTag} -m ${p} --dport 53 -j CVPN-DNS-OUT`);
    for (const addr of ['1.1.1.1', '8.8.8.8']) chains.push(`-A CVPN-DNS-OUT -s 10.99.0.2/32 -d ${addr}/32 -o tun0 -m comment --comment ${dnsTag} -j RETURN`);
    chains.push(`-A CVPN-DNS-OUT -d 127.0.0.0/8 -m comment --comment ${dnsTag} -j RETURN`, `-A CVPN-DNS-OUT -m comment --comment ${dnsTag} -j REJECT --reject-with icmp-port-unreachable`);
    chains.push(`-A CVPN-DNS-IN -i lo -m comment --comment ${dnsTag} -j ACCEPT`);
  } else {
    declarations.push('-N ' + v6Chain);
    for (const p of ['tcp', 'udp']) prefix.push(`-A OUTPUT ! -d ::1/128 -p ${p} -m comment --comment ${dnsTag} -m ${p} --dport 53 -j REJECT --reject-with icmp6-port-unreachable`);
    prefix.push(`-A OUTPUT -m comment --comment ${v6Tag} -j ${v6Chain}`);
    for (const spec of ['-o lo', '-d fe80::/10', '-d ff02::/16', '-s fd42:6376:706e::2/128 -d 2000::/3 -o tun0', '-s fd42:6376:706e::2/128 -d fd42:6376:706e::1/128 -o tun0']) chains.push(`-A ${v6Chain} ${spec} -m comment --comment ${v6Tag} -j RETURN`);
    chains.push(`-A ${v6Chain} -m comment --comment ${v6Tag} -j REJECT --reject-with icmp6-adm-prohibited`);
  }
  return ['-P INPUT ACCEPT', '-P FORWARD ACCEPT', '-P OUTPUT ACCEPT', ...declarations, ...prefix, ...hooks,
    '-A FORWARD -i usb0 -o wlan0 -j ACCEPT', '-A FORWARD -i wlan0 -o usb0 -j ACCEPT', ...rules, ...chains].join('\n') + '\n';
}
const audit = (family, input) => spawnSync('/bin/bash', [file, 'audit-snapshot', `--family=${family}`], {
  input, encoding: 'utf8', timeout: 3000, env: { PATH: '/no-tools', BASH_ENV: '/dev/null' },
});
for (const family of [4, 6]) {
  test(`offline active-client IPv${family} snapshot passes without root or any tools`, () => {
    const s = activeSnapshot(family), r = audit(family, s); assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /offline only/);
    assert.equal(audit(family, s.replaceAll('"', '')).status, 0); // legacy/unquoted canonical comments
  });
  for (const [name, change] of Object.entries({
    accept: s => s.replace('-A OUTPUT ', '-A OUTPUT -j ACCEPT\n-A OUTPUT '),
    return: s => s.replace('-A OUTPUT ', '-A OUTPUT -j RETURN\n-A OUTPUT '),
    unknown: s => s.replace('-A OUTPUT ', '-A OUTPUT -j FOREIGN\n-A OUTPUT '),
    commentOnly: s => s.replace('-A OUTPUT ', `-A OUTPUT -m comment --comment ${dnsTag} -j ACCEPT\n-A OUTPUT `),
    goto: s => s.replace(/-j (CVPN-DNS-OUT|CV6_[a-f0-9]+)/, '-g $1'),
    missing: s => s.replace('-A OUTPUT -m comment --comment cvks2-hook -j CLEANVPN_KS_OUT\n', ''),
    duplicate: s => s.replace('-A OUTPUT -m comment --comment cvks2-hook -j CLEANVPN_KS_OUT\n', '$&$&'),
    forwardPrefix: s => s.replace('-A FORWARD -m comment', '-A FORWARD -j ACCEPT\n-A FORWARD -m comment'),
    alteredGuard: s => s.replace('-A CLEANVPN_KS_OUT -j DROP', '-A CLEANVPN_KS_OUT -j ACCEPT'),
    acceptInChild: s => s.replace(family === 4 ? `--comment ${dnsTag} -j RETURN` : `--comment ${v6Tag} -j RETURN`, family === 4 ? `--comment ${dnsTag} -j ACCEPT` : `--comment ${v6Tag} -j ACCEPT`),
    nestedChild: s => s.replace(family === 4 ? `--comment ${dnsTag} -j RETURN` : `--comment ${v6Tag} -j RETURN`, family === 4 ? `--comment ${dnsTag} -j FOREIGN` : `--comment ${v6Tag} -j FOREIGN`),
    missingChild: s => s.split('\n').filter(l => !l.startsWith(family === 4 ? '-N CVPN-DNS-OUT' : '-N CV6_')).join('\n'),
    extraChild: s => s + (family === 4 ? `-A CVPN-DNS-OUT -j RETURN\n` : `-A ${v6Chain} -j RETURN\n`),
    wrongTun: s => s.replaceAll('-o tun0 -m comment', '-o wlan0 -m comment'),
  })) test(`IPv${family} snapshot refuses unsafe/unknown prefix: ${name}`, () => {
    const r = audit(family, change(activeSnapshot(family))); assert.notEqual(r.status, 0, r.stdout); assert.equal(r.stdout, '');
  });
}
test('offline audit has explicit scope and bounded input', () => {
  for (const args of [[], ['--family=4', '--server=1.1.1.1'], ['--family=inet'], ['--family=4', '--family=6']]) {
    const r = spawnSync('/bin/bash', [file, 'audit-snapshot', ...args], { encoding: 'utf8', timeout: 3000 }); assert.notEqual(r.status, 0);
  }
  assert.notEqual(audit(4, '').status, 0);
  assert.notEqual(audit(4, '-P OUTPUT ACCEPT\n' + 'x'.repeat(1048577)).status, 0);
  assert.notEqual(plan('--server=1.1.1.1', '--family=4').status, 0);
});
