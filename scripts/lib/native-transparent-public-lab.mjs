// Control/metadata only. TLS and all application bytes stay in C++ fixtures and
// two ordinary C++ engine processes. Never run network commands in the host ns.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';

const [build, cert, key, parent] = process.argv.slice(2);
const own = fs.readlinkSync('/proc/self/ns/net');
assert.match(parent, /^net:\[\d+\]$/); assert.notEqual(own, parent);
const run = (exe, args) => execFileSync(exe, args, { encoding: 'utf8', timeout: 12000, maxBuffer: 65536 });
const ip = (...args) => run('/usr/sbin/ip', args);
assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map(x => x.ifname), ['lo']);
// Durable admission deliberately rejects non-sticky world-writable ancestors;
// do not use an arbitrary TMPDIR override for this security-sensitive fixture.
const dir = fs.mkdtempSync('/tmp/cvpn-public-policy-');
const children = [];
const start = (exe, args) => {
  const child = spawn(exe, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  const entry = { child, lines: [], pending: '', ended: false, error: '', exit: null };
  child.on('error', e => { entry.error = e.code; entry.ended = true; });
  child.stdout.on('data', b => {
    entry.pending += b.toString();
    if (entry.pending.length > 65536 || entry.lines.length > 128) { entry.error = 'metadata_limit'; child.kill('SIGKILL'); return; }
    let end; while ((end = entry.pending.indexOf('\n')) >= 0) {
      try { entry.lines.push(JSON.parse(entry.pending.slice(0, end))); } catch { entry.error = 'invalid_metadata'; }
      entry.pending = entry.pending.slice(end + 1);
    }
  });
  child.stderr.on('data', b => { entry.error = (entry.error + b.toString()).slice(-4096); });
  child.on('exit', (code, signal) => { entry.ended = true; entry.exit = { code, signal }; });
  children.push(entry); return entry;
};
const wait = async (entry, check) => {
  const until = Date.now() + 5000;
  while (!check(entry)) {
    assert.equal(entry.ended, false, `unexpected child exit: ${entry.error}`);
    assert.ok(Date.now() < until, `metadata timeout: ${entry.error}`); await delay(10);
  }
};
const stop = async (entry, signal = 'SIGTERM') => {
  entry.child.kill(signal); await wait(entry, e => e.ended);
  if (signal === 'SIGTERM') assert.equal(entry.exit?.code, 0, entry.error);
};
try {
  ip('link', 'set', 'lo', 'up');
  const fixture = path.join(build, 'transparent-socket-test'), engine = path.join(build, 'clean-vpn-engine');
  const origin = start('/usr/bin/unshare', ['--net', fixture, '--public-origin', cert, key, own]);
  await wait(origin, e => e.lines.some(x => x.stage === 'namespace-ready'));
  ip('link', 'add', 'cvpublic0', 'type', 'veth', 'peer', 'name', 'cvpublic1');
  ip('link', 'set', 'cvpublic1', 'netns', String(origin.child.pid));
  ip('addr', 'add', '198.18.0.1/30', 'dev', 'cvpublic0'); ip('link', 'set', 'cvpublic0', 'up');
  ip('route', 'add', '1.1.1.1/32', 'via', '198.18.0.2', 'dev', 'cvpublic0');
  await wait(origin, e => e.lines.some(x => x.stage === 'origin-ready'));
  // The apparent Internet address belongs to a sibling lab namespace. There
  // is no physical interface/default route or path to the real 1.1.1.1 here.
  assert.equal(JSON.parse(ip('-j', 'route', 'show', 'default')).length, 0);
  fs.writeFileSync(path.join(dir, 'secret'), Buffer.alloc(32, 0x42), { mode: 0o600 });
  fs.mkdirSync(path.join(dir, 'replay'), { mode: 0o700 });
  const common = { version: 1, transport: 'transparent-tls', public_name: 'relay.example',
    secret_path: path.join(dir, 'secret'), destination_policy: { mode: 'public-https', deny_ipv4: ['8.8.8.0/24'] } };
  const exitCfg = { ...common, role: 'exit', listen: { ipv4: '127.0.0.1', port: 33001 }, replay_directory: path.join(dir, 'replay') };
  const clientCfg = { ...common, role: 'client', listen: { ipv4: '127.0.0.1', port: 33002 }, exit: exitCfg.listen };
  const ecfg = path.join(dir, 'exit.json'), ccfg = path.join(dir, 'client.json');
  fs.writeFileSync(ecfg, JSON.stringify(exitCfg)); fs.writeFileSync(ccfg, JSON.stringify(clientCfg));
  run(engine, ['--check-config', ecfg]); run(engine, ['--check-config', ccfg]);
  run(engine, ['--init-transparent-replay', ecfg]);
  let exit = start(engine, ['--config', ecfg, '--service']); await wait(exit, e => e.lines.some(x => x.state === 'listening'));
  const client = start(engine, ['--config', ccfg, '--service']); await wait(client, e => e.lines.some(x => x.state === 'listening'));
  run('/usr/sbin/iptables', ['-t', 'nat', '-A', 'OUTPUT', '-p', 'tcp', '--dport', '443', '-m', 'mark', '--mark', '66',
    '-j', 'REDIRECT', '--to-ports', '33002']);
  const probe = mode => run(fixture, [mode, cert, key, parent]);
  assert.match(probe('--public-client'), /TLS12\/TLS13-HRR PASS/);
  await wait(origin, e => e.lines.some(x => x.connections === 2));
  // Newly attached public-looking subnet must be denied without engine reload.
  ip('addr', 'add', '11.0.0.1/24', 'dev', 'lo');
  // A reachable sibling TLS endpoint in that connected prefix distinguishes
  // policy refusal from an accidental connect failure to a nonexistent host.
  ip('route', 'add', '11.0.0.2/32', 'via', '198.18.0.2', 'dev', 'cvpublic0');
  assert.match(probe('--public-probe'), /rejection PASS/);
  await stop(exit, 'SIGKILL');
  assert.match(probe('--public-client-blocked'), /no fallback PASS/);
  exit = start(engine, ['--config', ecfg, '--service']); await wait(exit, e => e.lines.some(x => x.state === 'listening'));
  assert.match(probe('--public-client'), /TLS12\/TLS13-HRR PASS/);
  await wait(origin, e => e.lines.some(x => x.connections === 4));
  // Policy is evaluated against changing interfaces on the client as well.
  ip('addr', 'add', '1.1.1.1/32', 'dev', 'lo');
  await stop(exit);
  // A decoy exit accepts TCP at the same endpoint; the C++ fixture verifies
  // that the client does not even attempt to connect to it for a local origin.
  assert.match(probe('--public-client-local'), /no fallback PASS/);
  await delay(50);
  assert.equal(origin.lines.filter(x => Number.isInteger(x.connections)).at(-1)?.connections, 4);
  await stop(client);
  console.log(JSON.stringify({ status: 'passed', kind: 'native-transparent-public-policy',
    originConnections: 4, tls: ['TLS1.2', 'TLS1.3-HRR'], isolatedNamespaces: 2,
    checks: ['public-policy-on-client-and-exit', 'special-and-configured-denials', 'dynamic-local-subnet-denial',
      'exit-crash-no-direct-fallback', 'restart-fresh-connections', 'dynamic-client-local-denial'],
    scope: 'synthetic-public-address-no-external-Internet-no-site-profile-acceptance' }));
} finally {
  for (const e of children) if (!e.ended) e.child.kill('SIGKILL');
  await Promise.all(children.map(e => e.ended ? null : new Promise(resolve => e.child.once('exit', resolve))));
  fs.rmSync(dir, { recursive: true, force: true });
}
