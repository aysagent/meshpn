import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { collectDnsDiagnostic, filterDiagnosticIni, parseDiagnosticArgs, DIAGNOSTIC_ENV } from './lib/dns-diagnostic.mjs';

function fixture({ systemd = true, owner = true } = {}) {
  const calls = [], reads = [];
  return { calls, reads, deps: {
    inspect: async () => ({ environment: { pid1: systemd ? 'systemd' : 'other' }, units: {} }),
    read: async (path) => { reads.push(path);
      if (path === '/etc/os-release') return 'ID=test\nVERSION_ID=1\nSECRET=do-not-report\n';
      if (path === '/etc/resolv.conf') return '# private comment\nnameserver 127.0.0.53\nsearch example.test\n';
      if (path === '/etc/nsswitch.conf') return 'passwd: files\nhosts: files dns # private comment\n';
      return '[Resolve]\nDNS=192.0.2.53#dns.example\nPrivateKey=never-report-key\n[Network]\nDHCP=yes\n';
    },
    list: async (path) => path === '/etc/systemd/network' ? ['10-uplink.network', '10-uplink.network.d', 'wg.netdev']
      : path === '/etc/systemd/network/10-uplink.network.d' ? ['20-dns.conf'] : [],
    find: async (name) => `/usr/bin/${name}`,
    run: async (file, args, options) => {
      calls.push({ file, args, options });
      let stdout = '';
      if (file.endsWith('/ip') && args.includes('link')) stdout = JSON.stringify([{ ifindex: 1, ifname: 'lo' }, { ifindex: 2, ifname: 'eth0' }]);
      if (file.endsWith('/busctl')) {
        if (args.includes('GetNameOwner')) {
          if (!owner) return { code: 1, reason: null, stdout: '', stderr: 'no owner', durationMs: 1 };
          stdout = JSON.stringify({ type: 's', data: [':1.42'] });
        } else if (args.includes('GetLink')) stdout = JSON.stringify({ type: 'o', data: ['/org/freedesktop/resolve1/link/_2'] });
        else stdout = JSON.stringify({ type: 's', data: 'fixture-property' });
      }
      return { code: 0, reason: null, stdout, stderr: '', durationMs: 1 };
    },
  } };
}

test('diagnostic CLI accepts only explicit bounded probe/help options', () => {
  assert.deepEqual(parseDiagnosticArgs([]), { probe: false });
  assert.deepEqual(parseDiagnosticArgs(['--probe']), { probe: true });
  for (const args of [['--apply'], ['--probe', '--probe'], ['--probe=example.org'], ['--config=/etc/shadow']]) {
    assert.throws(() => parseDiagnosticArgs(args));
    const r = spawnSync(process.execPath, ['scripts/dns-diagnostic.mjs', ...args], { encoding: 'utf8', timeout: 5000 });
    assert.equal(r.status, 1); assert.doesNotMatch(r.stdout, /BEGIN/);
  }
});

test('INI whitelist omits credentials/comments/other sections, retains TLS DNS names and clear assignments', () => {
  assert.deepEqual(filterDiagnosticIni('[Resolve]\nDNS=192.0.2.53#dns.example\nDNS=\nPrivateKey=SECRET\n# SECRET\n[Service]\nEnvironment=SECRET\n[DHCPv4]\nUseDNS=no\n'), [
    { section: 'Resolve', key: 'DNS', value: '192.0.2.53#dns.example' },
    { section: 'Resolve', key: 'DNS', value: '' }, { section: 'DHCPv4', key: 'UseDNS', value: 'no' },
  ]);
});

test('default gathers scoped evidence without network probes, setters, journals or process arguments', async () => {
  const f = fixture(), r = await collectDnsDiagnostic({}, f.deps);
  assert.equal(r.systemSettingsChanged, false); assert.equal(r.mode, 'inspection-only'); assert.deepEqual(r.probes, []);
  assert.ok(f.reads.includes('/etc/systemd/network/10-uplink.network.d/20-dns.conf'));
  assert.ok(!f.reads.some((p) => /netdev|shadow|\.env|cmdline/.test(p)));
  assert.doesNotMatch(JSON.stringify(r), /never-report-key|do-not-report|private comment/);
  for (const { file, args, options } of f.calls) {
    assert.ok(!/dig|getent|resolvectl|networkctl|nmcli|sudo|journalctl/.test(file));
    assert.ok(!args.some((a) => /^(Set|restart|start|enable|set-property|flush|revert)/.test(a)));
    assert.deepEqual(options.env, DIAGNOSTIC_ENV); assert.equal(options.timeoutMs, 3000); assert.equal(options.maxBytes, 8192);
    if (file.endsWith('/busctl')) {
      assert.ok(args.includes('--auto-start=no')); assert.ok(args.includes('--allow-interactive-authorization=no'));
      if (args.includes('get-property') || args.includes('GetLink')) assert.ok(args.includes(':1.42'));
    }
  }
  assert.equal(r.resolved.links.length, 1); assert.equal(r.resolved.links[0].name, 'eth0');
});

test('inactive resolver is never started and missing owner is preserved', async () => {
  const f = fixture({ owner: false }), r = await collectDnsDiagnostic({}, f.deps);
  assert.equal(r.resolved.owner.status, 'unavailable');
  assert.equal(f.calls.filter((c) => c.file.endsWith('/busctl')).length, 1);
});

test('non-systemd PID1 never contacts an exposed system bus', async () => {
  const f = fixture({ systemd: false }), r = await collectDnsDiagnostic({}, f.deps);
  assert.equal(r.resolved.status, 'not-probed-non-systemd');
  assert.ok(!f.calls.some((c) => c.file.endsWith('/busctl') || c.args.includes('show') && c.file.endsWith('/systemctl')));
});

test('explicit probes use only the current resolver and fixed name, test UDP/TCP A/AAAA', async () => {
  const f = fixture(), r = await collectDnsDiagnostic({ probe: true }, f.deps);
  assert.equal(r.probes.length, 5);
  const dig = f.calls.filter((c) => c.file.endsWith('/dig')); assert.equal(dig.length, 4);
  for (const { args } of dig) { assert.ok(args.includes('example.com')); assert.ok(!args.some((a) => a.startsWith('@'))); }
  assert.equal(dig.filter((c) => c.args.includes('+ignore') && c.args.includes('+notcp')).length, 2);
  assert.equal(dig.filter((c) => c.args.includes('+tcp')).length, 2);
});

test('missing tools and unreadable files produce a complete report without installation', async () => {
  const f = fixture(); f.deps.find = async () => null;
  f.deps.read = async () => { throw Object.assign(new Error('private pathname'), { code: 'EACCES' }); };
  const r = await collectDnsDiagnostic({ probe: true }, f.deps);
  assert.equal(r.files.resolvConf.reason, 'EACCES'); assert.equal(r.commands.links.reason, 'command-not-found');
  assert.equal(r.probes.length, 5); assert.equal(f.calls.length, 0); assert.doesNotMatch(JSON.stringify(r), /private pathname/);
});

test('deadline stops further commands and is not represented as a healthy diagnostic', async () => {
  const f = fixture(), run = f.deps.run;
  f.deps.run = async (...args) => { await delay(5); return run(...args); };
  const r = await collectDnsDiagnostic({ probe: true }, { ...f.deps, budgetMs: 1 });
  assert.equal(r.deadlineExceeded, true); assert.ok(r.probes.every((p) => p.result.reason === 'report-deadline'));
});

test('configuration and link inventories are bounded and truncation is explicit', async () => {
  const f = fixture(); f.deps.list = async () => Array.from({ length: 100 }, (_, n) => `${n}.network`);
  const r = await collectDnsDiagnostic({}, f.deps);
  assert.equal(f.reads.filter((p) => p.endsWith('.network')).length, 48);
  assert.equal(r.configDirectories['/etc/systemd/network'].truncated, true);
});

test('oversized filtered output and malformed bus data remain explicit failures', async () => {
  const f = fixture(); f.deps.read = async () => '[Resolve]\nDNS=' + 'a'.repeat(10000);
  const run = f.deps.run;
  f.deps.run = async (...args) => ({ ...await run(...args), ...(args[0].endsWith('/busctl') ? { stdout: '{}' } : {}) });
  const r = await collectDnsDiagnostic({}, f.deps);
  assert.equal(r.configs['/etc/systemd/resolved.conf'].reason, 'filtered-output-limit');
  assert.equal(r.resolved.owner.reason, 'invalid-bus-json'); assert.equal(r.resolved.status, 'unavailable-owner');
});
